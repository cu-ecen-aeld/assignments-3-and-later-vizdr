#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/syslog.h>
#include <fcntl.h>
#include <sys/queue.h>
#include <pthread.h>

#define PORT "9000"
#define BACKLOG 10       // how many pending connections queue will hold
#define MAXDATASIZE 1024 // max number of bytes we can get at once

bool g_sigterm = false;
bool g_sigint = false;

struct client_data
{
    int client_fd;
    char *client_addr_string;
    const char *path_storage_file;
};
// ========== Thread list entry ==========
struct thread_entry
{
    pthread_t tid;
    TAILQ_ENTRY(thread_entry)
    entries;
};

TAILQ_HEAD(thread_list, thread_entry);

struct thread_list finished_threads;
pthread_mutex_t list_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t list_cond = PTHREAD_COND_INITIALIZER;
// ========== Function prototypes ==========
int write_packet_to_file(const char *message, size_t message_size, const char *filename)
{
    if (message == NULL)
    {
        syslog(LOG_ERR, "NULL message pointer provided\n");
        return EXIT_FAILURE;
    }
    if (message_size == 0)
    {
        return EXIT_SUCCESS;
    }

    syslog(LOG_DEBUG, "Writing message %zu bytes to %s\n", message_size, filename);

    FILE *file = fopen(filename, "a");
    if (file == NULL)
    {
        syslog(LOG_ERR, "Error opening file %s: %m\n", filename);
        return EXIT_FAILURE;
    }

    size_t written = fwrite(message, 1, message_size, file);
    if (written != message_size)
    {
        syslog(
            LOG_ERR, "Error writing to file %s: tried to write %zu bytes, only %zu bytes written: %m\n",
            filename, message_size, written);
        fclose(file);
        return EXIT_FAILURE;
    }

    // Ensure data is flushed to disk
    if (fflush(file) != 0)
    {
        syslog(LOG_ERR, "Error flushing file %s: %m\n", filename);
        fclose(file);
        return EXIT_FAILURE;
    }

    fclose(file);
    return EXIT_SUCCESS;
}

int read_packet_from_file(char *message, size_t message_size, int pos, const char *filename)
{
    if (message_size == 0 || message == NULL)
    {
        syslog(LOG_WARNING, "0 buffer length provided or NULL message pointer\n");
        return -1;
    }
    if (pos < 0)
    {
        syslog(LOG_ERR, "Negative file position provided: %ld\n", (long)pos);
        return -1;
    }

    FILE *fd = fopen(filename, "r");
    if (fd == NULL)
    {
        syslog(LOG_ERR, "Error opening file %s: %m\n", filename);
        return -1;
    }

    if (fseeko(fd, pos, SEEK_SET) != 0)
    {
        syslog(LOG_ERR, "Error seeking file %s to position %ld: %m\n", filename, (long)pos);
        fclose(fd);
        return -1;
    }

    size_t read = fread(message, 1, message_size, fd);
    if (read < message_size && ferror(fd))
    {
        syslog(LOG_ERR, "Error reading file %s: %m\n", filename);
        fclose(fd);
        return -1;
    }

    fclose(fd);
    return (ssize_t)read;
}

int sendall(int socket_fd, const char *buf, size_t len)
{
    if (!buf || len == 0)
        return 0;

    size_t total = 0;
    ssize_t sent;

    while (total < len)
    {
        sent = send(socket_fd, buf + total, len - total, 0);
        if (sent == -1)
        {
            if (errno == EINTR)
                continue; // Retry on interrupt
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                // For non-blocking sockets, you might want to wait or retry
                continue;
            }
            syslog(LOG_ERR, "sendall failed to send %zu bytes: %m\n", len - total);
            return -1;
        }
        total += sent;
    }

    syslog(LOG_DEBUG, "sendall %zu bytes complete\n", total);
    return 0; // Success
}
// ========== Thread cleanup function ==========
void *cleanup_thread(void *arg)
{
    struct thread_entry *entry;

    while (1)
    {
        pthread_mutex_lock(&list_mutex);
        while (TAILQ_EMPTY(&finished_threads))
        {
            pthread_cond_wait(&list_cond, &list_mutex);
        }

        // Remove first finished thread
        entry = TAILQ_FIRST(&finished_threads);
        TAILQ_REMOVE(&finished_threads, entry, entries);
        pthread_mutex_unlock(&list_mutex);

        // Join outside lock
        pthread_join(entry->tid, NULL);
        free(entry);
    }

    return NULL;
}

// ========== Worker function ==========
void *handle_client(void *arg)
{
    struct client_data *client_info = (struct client_data *)arg;
    int client_fd = client_info->client_fd;
    char *client_addr_str = client_info->client_addr_string;
    const char *aesdsocketdata = client_info->path_storage_file;
    free(client_info->client_addr_string);
    free(client_info);

    // Allocate buffer for receiving data
    char *buffer = malloc(MAXDATASIZE);
    if (buffer == NULL)
    {
        syslog(LOG_ERR, "not enough memory: %m\n");
        close(client_fd);
        return EXIT_FAILURE;
    }

    long int received_num_bytes;
    ssize_t first_packet_length = 0;
    ssize_t second_packet_length = 0;
    char *second_packet = NULL;
    int size_to_send = 0;
    int pos = 0;

    if (buffer == NULL)
    {
        syslog(LOG_ERR, "not enough memory: %m\n");
        close(client_fd);
        return (void *)EXIT_FAILURE;
    }

    printf("Client connected (fd=%d)\n", client_fd);

    /*     while ((bytes = recv(client_fd, buffer, sizeof(buffer) - 1, 0)) > 0) {
            buffer[bytes] = '\0';
            printf("Client %d says: %s\n", client_fd, buffer);
            send(client_fd, buffer, bytes, 0); // echo back
        }
    */
    // Receive data and send back
    while ((received_num_bytes = recv(client_fd, buffer, MAXDATASIZE, 0)) > 0)
    {
        char *eol = memchr(buffer, '\n', received_num_bytes);
        if (eol != NULL)
        {
            // If we found a newline, which is end of packet, we first write to the file
            first_packet_length = eol - buffer + 1; // Include the newline character
            syslog(LOG_DEBUG, "Found packet delimiter at %ld\n", received_num_bytes);

            if (write_packet_to_file(buffer, received_num_bytes, aesdsocketdata) != EXIT_SUCCESS)
            {
                received_num_bytes = -1;
                break;
            }

            // Then receive the next packet if any
            second_packet_length = received_num_bytes - first_packet_length;
            second_packet = malloc(second_packet_length);

            if (second_packet == NULL)
            {
                syslog(LOG_ERR, "not enough memory for the next packet: %m\n");
                close(client_fd);
                free(buffer);
                return EXIT_FAILURE;
            }

            memcpy(second_packet, eol + 1, second_packet_length);

            while ((size_to_send = read_packet_from_file(buffer, MAXDATASIZE, pos, aesdsocketdata)) > 0)
            {
                pos += size_to_send;
                if (sendall(client_fd, buffer, size_to_send) == -1)
                {
                    syslog(LOG_ERR, "failed to send %d message to client %s\n", size_to_send, client_addr_str);
                    close(client_fd);
                    free(buffer);
                    free(second_packet);
                    return EXIT_FAILURE;
                }
                if (size_to_send != MAXDATASIZE)
                {
                    syslog(LOG_DEBUG, "End of file %d\n", pos);
                    break;
                }
            }

            if (size_to_send < 0)
            {
                close(client_fd);
                free(buffer);
                free(second_packet);
                return EXIT_FAILURE;
            }
            // Finally write the remaining part of the second packet if any
            if (write_packet_to_file(second_packet, second_packet_length, aesdsocketdata) != EXIT_SUCCESS)
            {
                received_num_bytes = -1;
                free(second_packet);
                break;
            }

            free(second_packet);

            second_packet = NULL;
            pos = 0;
            first_packet_length = 0;
            second_packet_length = 0;
            break; // Exit the receiving loop to wait for a new connection
        }
        else if (write_packet_to_file(buffer, received_num_bytes, aesdsocketdata) != EXIT_SUCCESS)
        {
            received_num_bytes = -1;
            break;
        }
    }

    if (received_num_bytes == -1)
    {
        syslog(LOG_ERR, "Failure - received bytes: %m\n");
    }
    else if (received_num_bytes == 0)
    {
        syslog(LOG_DEBUG, "Connection from %s closed\n", client_addr_str);
    }

    printf("Client disconnected (fd=%d)\n", client_fd);
    close(client_fd);
    free(buffer);
    free(second_packet);

    // Register myself in cleanup list
    struct thread_entry *entry = malloc(sizeof(struct thread_entry));
    if (entry)
    {
        entry->tid = pthread_self();
        pthread_mutex_lock(&list_mutex);
        TAILQ_INSERT_TAIL(&finished_threads, entry, entries);
        pthread_cond_signal(&list_cond);
        pthread_mutex_unlock(&list_mutex);
    }

    return NULL;
}
// ========== Signal handling ==========

void sig_handler(int s)
{
    if (s == SIGTERM)
    {
        g_sigterm = true;
    }
    else if (s == SIGINT)
    {
        g_sigint = true;
    }
}

int setup_sigaction()
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_handler = sig_handler;

    sigemptyset(&action.sa_mask);
    // No special flags
    action.sa_flags = 0;

    if (sigaction(SIGTERM, &action, NULL) == -1)
    {
        syslog(LOG_ERR, "signal action failed for SIGTERM: %m\n");
        return EXIT_FAILURE;
    }

    if (sigaction(SIGINT, &action, NULL) == -1)
    {
        syslog(LOG_ERR, "signal action failed for SIGINT: %m\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int run_aesd_server(int *socket_fd, const char *aesdsocketdata)
{
    int *connected_fd;
    struct sockaddr_storage client_addr;
    socklen_t client_addr_size;
    char client_addr_str[INET6_ADDRSTRLEN];

    /*     char *buf = NULL;
        ssize_t received_num_bytes;
        ssize_t first_packet_length = 0;
        ssize_t second_packet_length = 0;
        char* second_packet = NULL;
        int size_to_send = 0;
        int pos = 0; */

    if (socket_fd == NULL)
    {
        syslog(LOG_ERR, "NULL socket file descriptor pointer provided\n");
        return EXIT_FAILURE;
    }
    printf("aesd server: waiting for connections...\n");

    // Server is running. Main accept() loop
    while (!(g_sigint || g_sigterm))
    {
        connected_fd = malloc(sizeof(int));
        if (!connected_fd)
        {
            perror("malloc client fd");
            continue;
        }
        // memset(&client_addr, 0, sizeof client_addr);
        client_addr_size = sizeof client_addr;
        *connected_fd = accept(*socket_fd, (struct sockaddr *)&client_addr, &client_addr_size);
        if (*connected_fd == -1)
        {
            syslog(LOG_ERR, "accept");
            continue;
        }

        // Convert the IP to a string and print it
        memset(client_addr_str, 0, sizeof(client_addr_str));
        if (inet_ntop(client_addr.ss_family, &client_addr, client_addr_str, sizeof(client_addr_str)) == NULL)
        {
            syslog(LOG_ERR, "inet_ntop failure: %m\n");
            close(*connected_fd);
            continue;
        }

        syslog(LOG_DEBUG, "Accepted connection from %s\n", client_addr_str);

        // Create a thread to handle the client
        struct client_data *data = malloc(sizeof(struct client_data));
        if (!data)
        {
            perror("malloc");
            close(*connected_fd);
            continue;
        }
        data->client_fd = *connected_fd;
        data->client_addr_string = strdup(client_addr_str);
        if (!data->client_addr_string)
        {
            perror("strdup");
            close(*connected_fd);
            free(data);
            continue;
        }
        data->path_storage_file = aesdsocketdata;

        pthread_t tid;
        if (pthread_create(&tid, NULL, handle_client, data) != 0)
        {
            perror("pthread_create");
            close(*connected_fd);
            free(connected_fd);
        }
        
        // Don't detach — cleanup thread will join it later
        // close(connected_fd); // Moved to handle_client
    }

    return EXIT_SUCCESS;
}

int start_with_daemon(int *socket_fd)
{
    pid_t pid = fork();

    if (pid > 0)
    {
        return pid;
    }
    else if (pid < 0)
    {
        syslog(LOG_ERR, "Failure daemon fork: %m\n");
        return pid;
    }

    if (setsid() == -1)
    {
        syslog(LOG_ERR, "Failure daemon setsid: %m\n");
        return -1;
    }

    if (chdir("/") == -1)
    {
        syslog(LOG_ERR, "Failure daemon chdir: %m\n");
        return -1;
    }

    int maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd < 0 || maxfd > MAXDATASIZE)
    {
        maxfd = MAXDATASIZE;
    }

    // Cleanup: Close all open file descriptors
    for (int fd_cnt = 0; fd_cnt < maxfd; fd_cnt++)
    {
        if (*socket_fd != fd_cnt)
        {
            close(fd_cnt);
        }
    }

    // Daemon process launch: Open /dev/null and redirect stdin, stdout, stderr to it
    int fd = open("/dev/null", O_RDWR);
    if (fd < 0)
    {
        syslog(LOG_ERR, "Error openning file /dev/null: %m\n");
        return -1;
    }

    // Redirect stdin, stdout, stderr to /dev/null
    if (dup2(fd, STDIN_FILENO) < 0)
    {
        syslog(LOG_ERR, "dup2 stdin failed: %m");
        close(fd);
        return -1;
    }

    if (dup2(fd, STDOUT_FILENO) < 0)
    {
        syslog(LOG_ERR, "dup2 stdout failed: %m");
        close(fd);
        return -1;
    }

    if (dup2(fd, STDERR_FILENO) < 0)
    {
        syslog(LOG_ERR, "dup2 stderr failed: %m");
        close(fd);
        return -1;
    }

    // Check and close extra /dev/null fd, not stdin, stdout, or stderr
    if (fd > 2)
    {
        close(fd);
    }

    return pid;
}

int start_aesd_server(bool daemon, int *socket_fd, const char *filename)
{
    struct addrinfo hints, *addr_info, *ptr_it_addrinfo;
    int sockfd;
    int yes = 1;
    int ret_code;
    syslog(LOG_DEBUG, "Start server %s\n", daemon ? " (daemon)" : "");

    // Setup server socket
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;       // IPv4 only
    hints.ai_socktype = SOCK_STREAM; // TCP
    hints.ai_flags = AI_PASSIVE;     // Use my IP

    if ((ret_code = getaddrinfo(NULL, PORT, &hints, &addr_info)) != 0)
    {
        syslog(LOG_ERR, "getaddrinfo: %s, %m\n", gai_strerror(ret_code));
        return -1;
    }

    // Loop through all results and bind to the first we can
    for (ptr_it_addrinfo = addr_info; ptr_it_addrinfo != NULL; ptr_it_addrinfo = ptr_it_addrinfo->ai_next)
    {
        if ((sockfd = socket(ptr_it_addrinfo->ai_family, ptr_it_addrinfo->ai_socktype, ptr_it_addrinfo->ai_protocol)) == -1)
        {
            syslog(LOG_WARNING, "warning: socket %m\n");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
        {
            syslog(LOG_ERR, "error: setsockopt %m\n");
            close(sockfd);
            freeaddrinfo(addr_info);
            ptr_it_addrinfo = NULL;
            break;
        }

        if (bind(sockfd, ptr_it_addrinfo->ai_addr, ptr_it_addrinfo->ai_addrlen) == -1)
        {
            close(sockfd);
            syslog(LOG_ERR, "error: bind %m\n");
            continue;
        }

        break;
    }

    freeaddrinfo(addr_info);

    if (ptr_it_addrinfo == NULL)
    {
        syslog(LOG_ERR, "server: failed to bind\n");
        return -1;
    }

    if (listen(sockfd, BACKLOG) == -1)
    {
        syslog(LOG_ERR, "failed to listen: %m\n");
        close(sockfd);
        return -1;
    }

    if (sockfd == -1)
    {
        return EXIT_FAILURE;
    }

    // Pass socket fd back to main
    *socket_fd = sockfd;

    if (daemon)
    {
        pid_t pid = start_with_daemon(socket_fd);
        if (pid > 0)
        {
            syslog(LOG_DEBUG, "Shutdown daemon parent process. Child process pid %d\n", pid);
            return EXIT_SUCCESS;
        }
        else if (pid < 0)
        {
            close(*socket_fd);
            return EXIT_FAILURE;
        }

        syslog(LOG_DEBUG, "Started daemon in child process\n");
    }

    if ((ret_code = setup_sigaction()) != EXIT_SUCCESS)
    {
        syslog(LOG_ERR, "setup_sigaction failed with code %d\n", ret_code);
        return ret_code;
    }

    syslog(LOG_DEBUG, "Waiting for connections...\n");

    if (run_aesd_server(socket_fd, filename) != EXIT_SUCCESS)
    {
        close(*socket_fd);
        return EXIT_FAILURE;
    }

    if (unlink(filename) != 0)
    {
        syslog(LOG_WARNING, "%s delete failed: %m", filename);
    }

    close(*socket_fd);
    syslog(LOG_DEBUG, "Caught signal, exiting\n");
    return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
    TAILQ_INIT(&finished_threads);

    // Create cleanup thread
    pthread_t cleaner;
    pthread_create(&cleaner, NULL, cleanup_thread, NULL);
    pthread_detach(cleaner);

    int socket_fd;
    const char *aesdsocketdata = "/var/tmp/aesdsocketdata";
    truncate(aesdsocketdata, 0);

    if (argc == 1)
    {
        exit(start_aesd_server(false, &socket_fd, aesdsocketdata));
    }
    else if (argc == 2 && strcmp(argv[1], "-d") == 0)
    {
        exit(start_aesd_server(true, &socket_fd, aesdsocketdata));
    }
    else
    {
        syslog(LOG_ERR, "Invalid CLI arguments\n");
        return EXIT_FAILURE;
    }
}