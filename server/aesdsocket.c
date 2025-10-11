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
#include <pthread.h>
#include <sys/time.h>

#ifdef HAVE_SLIST_FOREACH_SAFE
#include <sys/queue.h>
#else
#include "queue.h"
#endif

#define PORT "9000"
#define BACKLOG 10       // how many pending connections queue will hold
#define MAXDATASIZE 1024 // max number of bytes we can get at once
// #define READWRITEFILETPATH "/var/tmp/aesdsocketdata"

// Add the build switch for char device
#ifdef USE_AESD_CHAR_DEVICE
#define READWRITEFILETPATH "/dev/aesdchar"
#else
#define READWRITEFILETPATH "/var/tmp/aesdsocketdata"
#endif

bool g_sigterm = false;
bool g_sigint = false;
// differs for char device
#ifndef USE_AESD_CHAR_DEVICE
FILE *fd = NULL; // File descriptor for read/write file
#else
int fd = -1; // File descriptor for char device
#endif

#ifndef USE_AESD_CHAR_DEVICE
pthread_mutex_t writer_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

// ========== Thread list entry ==========
struct thread_entry
{
    pthread_t conn_tid;
    int client_conn_fd;
    bool work_finished;
    char *client_addr_string;
    TAILQ_ENTRY(thread_entry)
    entries;
};

TAILQ_HEAD(thread_list, thread_entry);

struct thread_list launched_threads;

// ========== Function prototypes ==========
int write_packet_to_file(const char *message, size_t message_size)
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

    syslog(LOG_DEBUG, "Writing message %zu bytes to %s\n", message_size, READWRITEFILETPATH);
    // printf("Writing message %zu bytes to %s\n", message_size, READWRITEFILETPATH);

    if (fd == NULL)
    {
        syslog(LOG_ERR, "Error opening file %s: %m\n", READWRITEFILETPATH);
        return EXIT_FAILURE;
    }

#ifdef USE_AESD_CHAR_DEVICE
        // CHAR DEVICE IMPLEMENTATION
        // Open char device for writing
        fd = open(READWRITEFILETPATH, O_WRONLY);

        if(fd == -1)
        {
            syslog(LOG_ERR, "Failed to open char device for writing");
            return EXIT_FAILURE;
        }
        // Write data to char device
        if(write(fd, message, message_size) == -1)
        {
            syslog(LOG_ERR, "Failed to write to char device");
            close(fd);
            return EXIT_FAILURE;
        }
        close(fd);
        fd = -1;

        // Check if packet is complete and ends w/ newline
        if(memchr(message, '\n', message_size) != NULL)
        {
            // Open char device for reading back
            fd = open(READWRITEFILETPATH, O_RDONLY);
            if(fd == -1)
            {
                syslog(LOG_ERR, "Failed to open char device for reading");
                return EXIT_FAILURE;
            }
            // next : read content back from char device and send to client
        }

#else
    pthread_mutex_lock(&writer_mutex);
    size_t written = fwrite(message, 1, message_size, fd);
    if (written != message_size)
    {
        syslog(
            LOG_ERR, "Error writing to file %s: tried to write %zu bytes, only %zu bytes written: %m\n",
            READWRITEFILETPATH, message_size, written);
        fclose(fd);
        return EXIT_FAILURE;
    }

    // Ensure data is flushed to disk
    if (fflush(fd) != 0)
    {
        syslog(LOG_ERR, "Error flushing file %s: %m\n", READWRITEFILETPATH);
        fclose(fd);
        return EXIT_FAILURE;
    }
    pthread_mutex_unlock(&writer_mutex);
#endif
    return EXIT_SUCCESS;
}

void alarm_handler(int signo, siginfo_t *info, void *context)
{
    (void)signo;
    (void)info;
    (void)context;
    time_t rawtime;
    struct tm *timeinfo;
    char buffer[80];

    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(buffer, sizeof(buffer), "timestamp: %H:%M:%S\n", timeinfo);

    if (write_packet_to_file(buffer, strlen(buffer)) != EXIT_SUCCESS)
    {
        syslog(LOG_ERR, "Failed to write timestamp to file\n");
    }
}

void launch_periodic_timer()
{
    struct sigaction sa;
    struct itimerval timer_val;

    // Install timer_handler as the signal handler for SIGALRM.
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = alarm_handler;
    sigaction(SIGALRM, &sa, NULL);

    // Configure the timer to expire after 10 sec... */
    timer_val.it_value.tv_sec = 10;
    timer_val.it_value.tv_usec = 0;
    // ... and every 10 sec after that.
    timer_val.it_interval.tv_sec = 10;
    timer_val.it_interval.tv_usec = 0;
    // Start a real timer.
    if (setitimer(ITIMER_REAL, &timer_val, NULL) == -1)
    {
        perror("Error calling setitimer");
        return;
    }
    return;
}

int read_packet_from_file(char *message, size_t message_size, int pos)
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

    if (fd == NULL)
    {
        syslog(LOG_ERR, "Error opening file %s: %m\n", READWRITEFILETPATH);
        return -1;
    }

#ifdef USE_AESD_CHAR_DEVICE
    // CHAR DEVICE IMPLEMENTATION
    // Open char device for reading
    fd = open(READWRITEFILETPATH, O_RDONLY);
    if (fd == -1)
    {
        syslog(LOG_ERR, "Failed to open char device for reading");
        return -1;
    }

    // Seek to the specified position
    if (lseek(fd, pos, SEEK_SET) == (off_t)-1)
    {
        syslog(LOG_ERR, "Error seeking file %s to position %d: %m\n", READWRITEFILETPATH, pos);
        close(fd);
        return -1;
    }

    // Read data from char device
    ssize_t read_bytes = read(fd, message, message_size);
    if (read_bytes == -1)
    {
        syslog(LOG_ERR, "Error reading from char device: %m\n");
        close(fd);
        return -1;
    }

    close(fd);
    fd = -1;

    return read_bytes;

#else
    if (fseeko(fd, pos, SEEK_SET) != 0)
    {
        syslog(LOG_ERR, "Error seeking file %s to position %ld: %m\n", READWRITEFILETPATH, (long)pos);
        fclose(fd);
        return -1;
    }

    size_t read = fread(message, 1, message_size, fd);
    if (read < message_size && ferror(fd))
    {
        syslog(LOG_ERR, "Error reading file %s: %m\n", READWRITEFILETPATH);
        fclose(fd);
        return -1;
    }

#endif


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
#ifndef USE_AESD_CHAR_DEVICE
        if (sent == -1)
        {
            if (errno == EINTR)
                continue; // Retry on interrupt
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                // For non-blocking sockets, one might want to wait or retry
                continue;
            }
            syslog(LOG_ERR, "sendall failed to send %zu bytes: %m\n", len - total);
            return -1;
        }
#else
        if (sent <= 0)
        {
            syslog(LOG_ERR, "sendall failed to send %zu bytes: %m\n", len - total);
            return -1;
        }   
#endif
        total += sent;
    }

    syslog(LOG_DEBUG, "sendall %zu bytes complete\n", total);
    return 0; // Success
}
// ========== Thread cleanup function ==========
void *cleanup_thread(void *arg)
{
    struct thread_entry *entry;
    struct thread_entry *tmp_entry;
   // printf("Cleanup thread started\n");
    if (!g_sigint && !g_sigterm)
    {
        int count = 0;
        // Remove first finished thread
        entry = TAILQ_FIRST(&launched_threads);
        if (entry == NULL)
        {
            return NULL;
        }
        TAILQ_FOREACH_SAFE(entry, &launched_threads, entries, tmp_entry)
        {
            if (entry->work_finished)
            {
                pthread_join(entry->conn_tid, NULL);
                free(entry->client_addr_string);
                TAILQ_REMOVE(&launched_threads, entry, entries);
                free(entry);
            }
        }
        TAILQ_FOREACH(entry, &launched_threads, entries)
        {
            count++;
        }
        printf("Remains %d threads. Cleanup thread finished cleaning up\n", count);
    }

    // printf("Cleanup thread exiting\n");
    return NULL;
}

// ========== Worker function ==========
void *handle_client(void *arg)
{
    struct thread_entry *client_info = (struct thread_entry *)arg;
    if (client_info == NULL)
    {
        syslog(LOG_ERR, "NULL client info pointer provided\n");
        return (void *)EXIT_FAILURE;
    }
    // Allocate buffer for receiving data
    char *buffer = malloc(MAXDATASIZE);
    if (buffer == NULL)
    {
        syslog(LOG_ERR, "not enough memory: %m\n");
        close(client_info->client_conn_fd);
        free(client_info->client_addr_string);       
        free(client_info); 
        return (void *)EXIT_FAILURE;
    }

    long int received_num_bytes;
    ssize_t first_packet_length = 0;
    ssize_t second_packet_length = 0;
    char *second_packet = NULL;
    int size_to_send = 0;
    int pos = 0;

    printf("Client connected (fd=%d), (sent tid=%lu), current tid=%lu\n", client_info->client_conn_fd, (unsigned long)client_info->conn_tid, (unsigned long)pthread_self());

    // Receive data and send back
    while ((received_num_bytes = recv(client_info->client_conn_fd, buffer, MAXDATASIZE, 0)) > 0)
    {
        char *eol = memchr(buffer, '\n', received_num_bytes);
        if (eol != NULL)
        {
            // If we found a newline, which is end of packet, we first write to the file
            first_packet_length = eol - buffer + 1; // Include the newline character
            syslog(LOG_DEBUG, "Found packet delimiter at %ld\n", received_num_bytes);

            printf("Received %ld bytes from %s\n", received_num_bytes, client_info->client_addr_string);
            if (write_packet_to_file(buffer, received_num_bytes) != EXIT_SUCCESS)
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
                close(client_info->client_conn_fd);
                free(buffer);
                return (void *)EXIT_FAILURE;
            }

            memcpy(second_packet, eol + 1, second_packet_length);
            // Now we read back from the file and send to the client
            while ((size_to_send = read_packet_from_file(buffer, MAXDATASIZE, pos)) > 0)
            {
                pos += size_to_send;
                if (sendall(client_info->client_conn_fd, buffer, size_to_send) == -1)
                {
                    syslog(LOG_ERR, "failed to send %d message to client %s\n", size_to_send, client_info->client_addr_string);
                    close(client_info->client_conn_fd);
                    free(buffer);
                    free(second_packet);
                    return (void *)EXIT_FAILURE;
                }
                if (size_to_send != MAXDATASIZE)
                {
                    syslog(LOG_DEBUG, "End of file %d\n", pos);
                    break;
                }
            }
            if (size_to_send < 0)
            {
                close(client_info->client_conn_fd);
                free(buffer);
                free(second_packet);
                return (void *)EXIT_FAILURE;
            }
            // Finally write the remaining part of the second packet if any

            // printf("Writing remaining part of second packet\n");
            if (second_packet != NULL && second_packet_length > 0)
            {
                if (write_packet_to_file(second_packet, second_packet_length) != EXIT_SUCCESS)
                {
                    received_num_bytes = -1;
                    free(second_packet);
                    break;
                }
                free(second_packet);
            }
            free(second_packet);
            second_packet = NULL;
            pos = 0;
            first_packet_length = 0;
            second_packet_length = 0;
            break; // Exit the receiving loop to wait for a new connection
        }
        else
        {
            // No newline found, just write what we have to the file and continue receiving
            if (write_packet_to_file(buffer, received_num_bytes) != EXIT_SUCCESS)
            {
                received_num_bytes = -1;
                break;
            }
            syslog(LOG_DEBUG, "No packet delimiter found in %ld bytes\n", received_num_bytes);
        }
    }

    if (received_num_bytes == -1)
    {
        syslog(LOG_ERR, "Failure - received bytes: %m\n");
    }
    else if (received_num_bytes == 0)
    {
        syslog(LOG_DEBUG, "Connection from %s closed\n", client_info->client_addr_string);
    }

    // printf("Client disconnected (fd=%d)\n", client_info->client_conn_fd);
    // Cleanup resources
    close(client_info->client_conn_fd);
    free(buffer);
    free(second_packet);
    second_packet = NULL;
    free(client_info->client_addr_string);
    client_info->client_addr_string = NULL;

    // Mark work as finished
    client_info->work_finished = true;

    return NULL;
}
// ========== Signal handling ==========

void cleanup()
{
    // printf("Cleaning up resources started\n");
    // Cleanup resources
#ifndef USE_AESD_CHAR_DEVICE
    pthread_mutex_destroy(&writer_mutex);
    fclose(fd);
#else
    if (fd != -1)
    {
        close(fd);
        fd = -1;
    }
#endif
    // Close all client connections and join threads  
    // Free any remaining threads in the finished list
    struct thread_entry *entry;
    while (!TAILQ_EMPTY(&launched_threads))
    {
        entry = TAILQ_FIRST(&launched_threads);
        TAILQ_REMOVE(&launched_threads, entry, entries);
        pthread_join(entry->conn_tid, NULL);
        free(entry->client_addr_string);
        free(entry);
    }
    remove(READWRITEFILETPATH);
    // printf("Server exiting\n");
    syslog(LOG_DEBUG, "Server exiting\n");
    closelog();
    return;
}

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
    if (g_sigint || g_sigterm)
    {
        cleanup();
        exit(EXIT_SUCCESS);
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
    int connected_fd;
    int *ptr_conn_fd = &connected_fd;
    struct sockaddr_storage client_addr;
    socklen_t client_addr_size;
    char client_addr_str[INET6_ADDRSTRLEN];

    if (socket_fd == NULL)
    {
        syslog(LOG_ERR, "NULL socket file descriptor pointer provided\n");
        return EXIT_FAILURE;
    }
    printf("aesd server: waiting for connections...\n");
// removed for char device
#ifndef USE_AESD_CHAR_DEVICE
    fd = fopen(READWRITEFILETPATH, "a+");
    if (!fd)
    {
        syslog(LOG_ERR, "Failed to open file: %m\n");
        return EXIT_FAILURE;
    }

    launch_periodic_timer();
#endif

    // Server is running. Main accept() loop
    while (!g_sigterm && !g_sigint)
    {
        memset(&client_addr, 0, sizeof client_addr);
        client_addr_size = sizeof client_addr;
        connected_fd = accept(*socket_fd, (struct sockaddr *)&client_addr, &client_addr_size);
        if (connected_fd == -1)
        {
            syslog(LOG_ERR, "accept");
            continue;
        }

        // Convert the IP to a string and print it
        memset(client_addr_str, 0, sizeof(client_addr_str));
        if (inet_ntop(client_addr.ss_family, &client_addr, client_addr_str, sizeof(client_addr_str)) == NULL)
        {
            syslog(LOG_ERR, "inet_ntop failure: %m\n");
            continue;
        }
        // printf("Accepted connection from %s\n", client_addr_str);
        syslog(LOG_DEBUG, "Accepted connection from %s\n", client_addr_str);

        // Create a thread to handle the client         
        struct thread_entry *entry = malloc(sizeof(struct thread_entry));
        if (entry)
        {
            entry->client_conn_fd = *ptr_conn_fd;
            entry->client_addr_string = strdup(client_addr_str);
            entry->work_finished = false;

            TAILQ_INSERT_TAIL(&launched_threads, entry, entries);
        }

        if (pthread_create(&entry->conn_tid, NULL, handle_client, entry) != 0)
        {
            perror("pthread_create");
            free(entry->client_addr_string);
            free(entry);
            close(*ptr_conn_fd);
            continue;
        }
        // printf("Launched thread %lu for client %s (fd=%d)\n", (unsigned long)entry->conn_tid, client_addr_str, *ptr_conn_fd);

        // Don't detach — cleanup thread will join it later
        cleanup_thread(NULL);
    }

    cleanup();
    return EXIT_SUCCESS;
}

int start_aesd_server(bool daemon_mode, int *socket_fd)
{
    struct addrinfo hints, *addr_info, *ptr_it_addrinfo;
    int sockfd;
    int yes = 1;
    int ret_code;
    syslog(LOG_DEBUG, "Start server %s\n", daemon_mode ? " (daemon)" : "");

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

    if (daemon_mode)
    {
        // Daemonize the process with librarry call
        if (daemon(0, 0) == -1)
        {
            syslog(LOG_ERR, "Failed to daemonize");
            return -1;
        }

        syslog(LOG_DEBUG, "Started daemon in child process\n");
    }

    if ((ret_code = setup_sigaction()) != EXIT_SUCCESS)
    {
        syslog(LOG_ERR, "setup_sigaction failed with code %d\n", ret_code);
        return ret_code;
    }

    syslog(LOG_DEBUG, "Waiting for connections...\n");

    if (run_aesd_server(socket_fd, READWRITEFILETPATH) != EXIT_SUCCESS)
    {
        close(*socket_fd);
        return EXIT_FAILURE;
    }
#ifndef USE_AESD_CHAR_DEVICE
    if (unlink(READWRITEFILETPATH) != 0)
    {
        syslog(LOG_WARNING, "%s delete failed: %m", READWRITEFILETPATH);
    }
#endif
    close(*socket_fd);
    syslog(LOG_DEBUG, "Caught signal, exiting\n");
    return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
    TAILQ_INIT(&launched_threads);

    int socket_fd;

    truncate(READWRITEFILETPATH, 0);

    if (argc == 1)
    {
        exit(start_aesd_server(false, &socket_fd));
    }
    else if (argc == 2 && strcmp(argv[1], "-d") == 0)
    {
        exit(start_aesd_server(true, &socket_fd));
    }
    else
    {
        syslog(LOG_ERR, "Invalid CLI arguments\n");
        return EXIT_FAILURE;
    }
}