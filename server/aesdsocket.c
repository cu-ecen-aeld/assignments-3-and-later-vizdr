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
#include <syslog.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/time.h>
// #include <sys/ioctl.h> // Moved to aesd_ioctl.h
#include "../aesd-char-driver/aesd_ioctl.h"

#ifdef HAVE_SLIST_FOREACH_SAFE
#include <sys/queue.h>
#else
#include "queue.h"
#endif

#define PORT "9000"
#define BACKLOG 10       // how many pending connections queue will hold
#define MAXDATASIZE 1024 // max number of bytes we can get at once

// Add the build switch for char device
#if USE_AESD_CHAR_DEVICE
#define READWRITEFILETPATH "/dev/aesdchar"
#else
#define READWRITEFILETPATH "/var/tmp/aesdsocketdata"
#endif

bool g_sigterm = false;
bool g_sigint = false;

volatile sig_atomic_t timer_fired = 0;
volatile sig_atomic_t ioctl_seek_requested = 0;
int write_cmd = 0;
int write_cmd_offset = 0;

#if !USE_AESD_CHAR_DEVICE
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
int write_packet_to_file(int data_file_fd, const char *message, size_t message_size);
int respond_to_client(int data_file_fd, int client_fd);

void alarm_handler(int signo, siginfo_t *info, void *context);
void launch_periodic_timer();

void *cleanup_thread(void *arg);
void cleanup();

void *handle_client(void *arg);

void check_seek_ioctl_requested(int bytes_received, char *buffer, unsigned int *write_cmd, unsigned int *write_cmd_offset);

void sig_handler(int signo);
int setup_sigaction();

int run_aesd_server(int *socket_fd, const char *aesdsocketdata);
int start_aesd_server(bool daemon_mode, int *socket_fd);

// ========== File read/write functions ==========
int write_packet_to_file(int data_file_fd, const char *message, size_t message_size)
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

    syslog(LOG_DEBUG, "Writing message %zd bytes to %s\n", message_size, READWRITEFILETPATH);
    printf("Writing message %zd bytes to %s\n", message_size, READWRITEFILETPATH);

    // TODO move open outside of the function
    int fd = data_file_fd;

    if (fd == -1)
    {
        syslog(LOG_ERR, "Error opening file %s: %m\n", READWRITEFILETPATH);
        return EXIT_FAILURE;
    }

#if !USE_AESD_CHAR_DEVICE
    pthread_mutex_lock(&writer_mutex);
#endif
    ssize_t written = write(fd, message, message_size); // use ssize_t for message_size
    printf("Wrote %zd bytes to %s\n", written, READWRITEFILETPATH);
    if (written != (ssize_t)message_size)
    {
        // printf("Partial write: tried to write %zu bytes, only %zu bytes written\n", message_size, written);
        syslog(
            LOG_ERR, "Error writing to file %s: tried to write %zd bytes, only %zd bytes written: %m\n",
            READWRITEFILETPATH, message_size, written);
        close(fd);
        fd = -1;
#if !USE_AESD_CHAR_DEVICE
        pthread_mutex_unlock(&writer_mutex);
#endif
        return EXIT_FAILURE;
    }

#if !USE_AESD_CHAR_DEVICE
    // Ensure data is flushed to disk
    // Only flush for regular files
    if (fsync(fd) != 0)
    {
        // printf("Error flushing file %s: %m\n", READWRITEFILETPATH);
        syslog(LOG_ERR, "Error flushing file %s: %m\n", READWRITEFILETPATH);
        close(fd);
        fd = -1;

        pthread_mutex_unlock(&writer_mutex);
        return EXIT_FAILURE;
    }
#endif
/*     close(fd);
    fd = -1; */
#if !USE_AESD_CHAR_DEVICE
    pthread_mutex_unlock(&writer_mutex);
#endif
    return EXIT_SUCCESS;
}

int respond_to_client(int file_fd, int client_fd)
{
    // read and send back the entire content of the file
    if (file_fd == -1 || client_fd < 0)
    {
        syslog(LOG_ERR, "Invalid parameters to respond_to_client\n");
        return EXIT_FAILURE;
    }
    int data_fd = file_fd;
    // Read back the entire content
    // Use the same fd to ensure f_pos is maintained
    char *temp_read_buf = malloc(MAXDATASIZE);
    memset(temp_read_buf, 0, MAXDATASIZE);
    ssize_t read_len = 0;

    while ((read_len = read(data_fd, temp_read_buf, MAXDATASIZE)) > 0)
    {
        ssize_t total_sent = 0;
        while (total_sent < read_len)
        {
            ssize_t sent = send(client_fd, temp_read_buf + total_sent, read_len - total_sent, 0);
            if (sent == -1)
            {
                if (errno == EINTR)
                {
                    continue; // retry sending when interrupted
                }
                syslog(LOG_ERR, "Failed to send data to client");
                free(temp_read_buf);
                return EXIT_FAILURE;
            }
            total_sent += sent;
            syslog(LOG_DEBUG, "Sent %zd bytes to client", sent);
        }
    }
    if (read_len == -1)
    {
        syslog(LOG_ERR, "Failed to send data to client");
        free(temp_read_buf);
        return EXIT_FAILURE;
    }
    free(temp_read_buf);
    return EXIT_SUCCESS;
}

// ========== Timer functions ==========
void alarm_handler(int signo, siginfo_t *info, void *context)
{
    (void)signo;
    (void)info;
    (void)context;
    timer_fired = 1; // flag for periodic work outside signal context
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

// ========== cleanup functions ==========
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

void cleanup()
{
    // printf("Cleaning up resources started\n");
    // Cleanup resources
#if !USE_AESD_CHAR_DEVICE
    pthread_mutex_destroy(&writer_mutex);
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
#if !USE_AESD_CHAR_DEVICE
    printf("Deleting data file %s\n", READWRITEFILETPATH);
    remove(READWRITEFILETPATH);
#endif
    // printf("Server exiting\n");
    syslog(LOG_DEBUG, "Server exiting\n");
    closelog();
    return;
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
    int data_file_fd = -1;
    // Allocate buffer for receiving data
    char *recv_buf = malloc(MAXDATASIZE);
    size_t recv_buf_size = 0;
    ssize_t recv_bytes = 0;

    if (recv_buf == NULL)
    {
        syslog(LOG_ERR, "not enough memory: %m\n");
        close(client_info->client_conn_fd);
        free(client_info->client_addr_string);
        free(client_info);
        return (void *)EXIT_FAILURE;
    }

#if USE_AESD_CHAR_DEVICE
    // Open char device once per connection and keep it open
    data_file_fd = open(READWRITEFILETPATH, O_RDWR);
    if (data_file_fd == -1)
    {
        syslog(LOG_ERR, "Failed to open char device");
        client_info->work_finished = true;
        close(client_info->client_conn_fd);
        pthread_exit(NULL);
    }
    syslog(LOG_DEBUG, "Opened char device fd: %d", data_file_fd);
#else
    // Open file to enter data (original implementation)
    data_file_fd = open(READWRITEFILETPATH, O_CREAT | O_APPEND | O_RDWR, 0644);
    if (data_file_fd == -1)
    {
        syslog(LOG_ERR, "Failed to open data file");
        client_info->work_finished = true;
        close(client_info->client_conn_fd);
        pthread_exit(NULL);
    }
#endif

    memset(recv_buf, 0, MAXDATASIZE);
    printf("Client connected (fd=%d), (sent tid=%lu), current tid=%lu\n", client_info->client_conn_fd, (unsigned long)client_info->conn_tid, (unsigned long)pthread_self());

    // Receive data and send back
    while ((recv_bytes = recv(client_info->client_conn_fd, recv_buf, MAXDATASIZE - 1u, 0)) > 0)
    {
        // printf("Received %zd bytes from client %s: %s\n", recv_bytes);
        recv_buf[recv_bytes] = '\0';
        syslog(LOG_DEBUG, "Received %zd bytes: %s", recv_bytes, recv_buf);
        // Look for end-of-line in the accumulated data
        check_seek_ioctl_requested(recv_bytes, recv_buf, (unsigned int *)&write_cmd, (unsigned int *)&write_cmd_offset);

        if (ioctl_seek_requested)
        {
            // Process the seek command
            struct aesd_seekto seekto;
            seekto.write_cmd = write_cmd;
            seekto.write_cmd_offset = write_cmd_offset;

            if (ioctl(data_file_fd, AESDCHAR_IOCSEEKTO, &seekto) == -1)
            {
                syslog(LOG_ERR, "AESDCHAR_IOCSEEKTO ioctl failed: %m");
            }
            else
            {
                syslog(LOG_DEBUG, "AESDCHAR_IOCSEEKTO ioctl succeeded: cmd=%u, offset=%u",
                       seekto.write_cmd, seekto.write_cmd_offset);
            }
            ioctl_seek_requested = 0; // reset flag
        }
        else // Normal data write to char device or file
        {
            // Normal data write
            if (write_packet_to_file(data_file_fd, recv_buf, recv_bytes) != EXIT_SUCCESS)
            {
                syslog(LOG_ERR, "Failed to write packet to file\n");
            }

            // Check if packet is complete and ends with newline
            if (memchr(recv_buf, '\n', recv_bytes) != NULL)
            {
#if !USE_AESD_CHAR_DEVICE
                pthread_mutex_lock(&writer_mutex);
#endif
                syslog(LOG_DEBUG, "Packet complete, reading back all content");

                // Save current position
                off_t current_pos = lseek(data_file_fd, 0, SEEK_CUR);

                // Read back ALL content from the beginning for normal writes
                lseek(data_file_fd, 0, SEEK_SET);

                respond_to_client(data_file_fd, client_info->client_conn_fd);
                // Restore position
                lseek(data_file_fd, current_pos, SEEK_SET);
#if !USE_AESD_CHAR_DEVICE
                pthread_mutex_unlock(&writer_mutex);
#endif
            }
        }
    }

    if (recv_bytes < 0)
    {
        syslog(LOG_ERR, "Failure - received bytes: %m\n");
    }
    else if (recv_bytes == 0)
    {
        syslog(LOG_DEBUG, "Connection from %s closed\n", client_info->client_addr_string);
    }

    // printf("Client disconnected (fd=%d)\n", client_info->client_conn_fd);
    syslog(LOG_DEBUG, "Client disconnected (fd=%d)\n", client_info->client_conn_fd);
    // Cleanup resources
    close(client_info->client_conn_fd);
    free(recv_buf);

    free(client_info->client_addr_string);
    client_info->client_addr_string = NULL;
    close(data_file_fd);
    data_file_fd = -1;
    // Mark work as finished
    client_info->work_finished = true;

    return NULL;
}

// ========== IOCTL seek check function ==========
void check_seek_ioctl_requested(int bytes_received, char *buffer, unsigned int *write_cmd, unsigned int *write_cmd_offset)
{
    const char prefix[] = "AESDCHAR_IOCSEEKTO:";
    const size_t prefix_len = sizeof(prefix) - 1; /* 19 */

    ioctl_seek_requested = 0;
    if (bytes_received >= (int)prefix_len && strncmp(buffer, prefix, prefix_len) == 0)
    {
        /* trim trailing whitespace */
        char *seek_buffer = buffer;
        size_t seek_len = (size_t)bytes_received;
        while (seek_len > 0 && (seek_buffer[seek_len - 1] == '\n' ||
                                seek_buffer[seek_len - 1] == '\r' ||
                                seek_buffer[seek_len - 1] == ' '))
        {
            seek_buffer[--seek_len] = '\0';
        }

        if (sscanf(seek_buffer + prefix_len, "%u,%u", write_cmd, write_cmd_offset) == 2)
        {
            syslog(LOG_DEBUG, "Processing seek command: cmd=%u, offset=%u",
                   *write_cmd, *write_cmd_offset);
            ioctl_seek_requested = 1;
        }
        else
        {
            syslog(LOG_ERR, "Failed to parse seek command: '%s'", seek_buffer + prefix_len);
        }
    }
}

// ========== Signal handling functions ==========
void sig_handler(int signo)
{
    if (signo == SIGTERM)
    {
        g_sigterm = true;
    }
    else if (signo == SIGINT)
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

// ========== Server main functions ==========
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
    //    launch_periodic_timer();

    // Server is running. Main accept() loop
    while (!g_sigterm && !g_sigint)
    {
        if (timer_fired)
        {
            time_t rawtime;
            struct tm timeinfo;
            char buffer[64];

            time(&rawtime);
            localtime_r(&rawtime, &timeinfo);

            strftime(buffer, sizeof(buffer), "timestamp: %H:%M:%S\n", &timeinfo);
            int data_file_fd = open(aesdsocketdata, O_CREAT | O_APPEND | O_RDWR, 0644);
            if (data_file_fd == -1)
            {
                syslog(LOG_ERR, "Failed to open data file for timestamp write\n");
            }
            else
            {
                syslog(LOG_DEBUG, "Opened data file for timestamp write, fd=%d\n", data_file_fd);
            }
            if (write_packet_to_file(data_file_fd, buffer, strlen(buffer)) != EXIT_SUCCESS)
            {
                syslog(LOG_ERR, "Failed to write timestamp to file\n");
            }

            timer_fired = 0; // reset flag
        }

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
        }

        if (pthread_create(&entry->conn_tid, NULL, handle_client, entry) != 0)
        {
            perror("pthread_create");
            free(entry->client_addr_string);
            free(entry);
            close(*ptr_conn_fd);
            continue;
        }

        TAILQ_INSERT_TAIL(&launched_threads, entry, entries);
        // printf("Launched thread %lu for client %s (fd=%d)\n", (unsigned long)entry->conn_tid, client_addr_str, *ptr_conn_fd);

        // Don't detach — cleanup thread will join it later
    }
    cleanup_thread(NULL);
    cleanup();
    return EXIT_SUCCESS;
}

int start_aesd_server(bool daemon_mode, int *socket_fd)
{
    struct addrinfo hints, *addr_info, *ptr_it_addrinfo;
    int sockfd;
    int yes = 1;
    int ret_code;
    int fd = -1;
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
#if !USE_AESD_CHAR_DEVICE
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

    openlog("aesdsocket", LOG_PID, LOG_USER);

#if !USE_AESD_CHAR_DEVICE
    int fd = open(READWRITEFILETPATH, O_RDWR | O_CREAT, 0666);
    if (fd == -1)
    {
        perror("open");
        return EXIT_FAILURE;
    }
    if (ftruncate(fd, 0) != 0)
    {
        perror("ftruncate");
        close(fd);
        return EXIT_FAILURE;
    }
    close(fd);
#endif
    if (argc == 1)
    {
        exit(start_aesd_server(false, &socket_fd));
    }
    else if (argc == 2 && strcmp(argv[1], "-d") == 0)
    {
        printf("Starting in daemon mode\n");
        exit(start_aesd_server(true, &socket_fd));
    }
    else
    {
        syslog(LOG_ERR, "Invalid CLI arguments\n");
        return EXIT_FAILURE;
    }
}