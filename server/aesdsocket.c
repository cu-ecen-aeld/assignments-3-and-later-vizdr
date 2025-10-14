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

// Add the build switch for char device
#if USE_AESD_CHAR_DEVICE
#define READWRITEFILETPATH "/dev/aesdchar"
#else
#define READWRITEFILETPATH "/var/tmp/aesdsocketdata"
#endif

bool g_sigterm = false;
bool g_sigint = false;

volatile sig_atomic_t timer_fired = 0;

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
int write_packet_to_file(const char *message, size_t message_size)
{
    int fd = -1;
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

#if USE_AESD_CHAR_DEVICE
    // For the character device: open without O_CREAT or O_APPEND
    fd = open(READWRITEFILETPATH, O_WRONLY);
#else
    // For the regular file: allow creation and append
    fd = open(READWRITEFILETPATH, O_WRONLY | O_APPEND | O_CREAT, 0666);
#endif

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
    close(fd);
    fd = -1;
#if !USE_AESD_CHAR_DEVICE
    pthread_mutex_unlock(&writer_mutex);
#endif
    return EXIT_SUCCESS;
}

void alarm_handler(int signo, siginfo_t *info, void *context)
{
    (void)signo;
    (void)info;
    (void)context;
    timer_fired = 1; // flag for periodic work outside signal context
    /* time_t rawtime;
    struct tm *timeinfo;
    char buffer[80];

    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(buffer, sizeof(buffer), "timestamp: %H:%M:%S\n", timeinfo);

    if (write_packet_to_file(buffer, strlen(buffer)) != EXIT_SUCCESS)
    {
        syslog(LOG_ERR, "Failed to write timestamp to file\n");
    } */
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

int read_packet_from_file(char **buffer, size_t *length)
{
    int fd = -1;
    if (buffer == NULL || length == NULL)
    {
        syslog(LOG_ERR, "NULL buffer or length pointer provided\n");
        return EXIT_FAILURE;
    }

    // Dynamically allocate buffer and read entire file content
    // Resize buffer as needed

    ssize_t bytes_read;
    size_t total_read = 0;
    size_t buf_size = 1024;
    char *temp = malloc(buf_size);

    if (!temp)
    {
        syslog(LOG_ERR, "Memory allocation failed\n");
        return EXIT_FAILURE;
    }

#if USE_AESD_CHAR_DEVICE
    fd = open(READWRITEFILETPATH, O_NONBLOCK | O_RDONLY);
#else
    pthread_mutex_lock(&writer_mutex);
    fd = open(READWRITEFILETPATH, O_RDONLY);
#endif
    
    if (fd == -1)
    {
        syslog(LOG_ERR, "Error opening %s for reading: %m\n", READWRITEFILETPATH);
#if !USE_AESD_CHAR_DEVICE
        pthread_mutex_unlock(&writer_mutex);
#endif
        free(temp);
        return EXIT_FAILURE;
    }

    while ((bytes_read = read(fd, temp + total_read, buf_size - total_read)) > 0)
    {
        total_read += bytes_read;
        if (total_read == buf_size)
        {
            buf_size *= 2;
            char *new_buf = realloc(temp, buf_size);
            if (!new_buf)
            {
                syslog(LOG_ERR, "Realloc failed\n");
                free(temp);
                close(fd);
#if !USE_AESD_CHAR_DEVICE
                pthread_mutex_unlock(&writer_mutex);
#endif
                return EXIT_FAILURE;
            }
            temp = new_buf;
        }
    }

    if (bytes_read < 0)
    {
        syslog(LOG_ERR, "Error reading from %s: %m\n", READWRITEFILETPATH);
    }

    close(fd);
#if !USE_AESD_CHAR_DEVICE
    pthread_mutex_unlock(&writer_mutex);
#endif

    *buffer = temp;
    *length = total_read;

    syslog(LOG_DEBUG, "Read %zu bytes from %s\n", total_read, READWRITEFILETPATH);
    printf("Read %zu bytes from %s\n", total_read, READWRITEFILETPATH);

    return EXIT_SUCCESS;
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
#if !USE_AESD_CHAR_DEVICE
            if (errno == EINTR)
                continue; // Retry on interrupt
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                // For non-blocking sockets, one might want to wait or retry
                continue;
            }
#endif
            syslog(LOG_ERR, "sendall failed to send %zu bytes: %m\n", len - total);
            return -1;
        }
        total += sent;
    }

    syslog(LOG_DEBUG, "sendall %zu bytes complete\n", total);
    printf("sendall %zu bytes complete\n", total);
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
    char *recv_buf = malloc(MAXDATASIZE);
    size_t recv_buf_size = 0;
    ssize_t recv_bytes = 0;
    char *newline_ptr;
    char *packet = NULL;
    size_t packet_len = 0;
    char *read_buf = NULL;
    size_t read_len = 0;

    if (recv_buf == NULL)
    {
        syslog(LOG_ERR, "not enough memory: %m\n");
        close(client_info->client_conn_fd);
        free(client_info->client_addr_string);
        free(client_info);
        return (void *)EXIT_FAILURE;
    }

    memset(recv_buf, 0, MAXDATASIZE);
    printf("Client connected (fd=%d), (sent tid=%lu), current tid=%lu\n", client_info->client_conn_fd, (unsigned long)client_info->conn_tid, (unsigned long)pthread_self());

    // Receive data and send back
    while ((recv_bytes = recv(client_info->client_conn_fd, recv_buf + recv_buf_size, MAXDATASIZE - recv_buf_size, 0)) > 0)
    {
        recv_buf_size += recv_bytes;
        recv_buf[recv_buf_size] = '\0';

        // Look for end-of-line in the accumulated data
        newline_ptr = strchr(recv_buf, '\n');
        if (!newline_ptr)
        {
            // Continue receiving until full line received
            if (recv_buf_size >= MAXDATASIZE)
            {
                syslog(LOG_ERR, "Received data exceeds buffer limit\n");
                break;
            }
            continue;
        }

        // We found a full packet (line)
        packet_len = newline_ptr - recv_buf + 1;
        packet = malloc(packet_len);
        if (!packet)
        {
            syslog(LOG_ERR, "malloc failed for packet: %m\n");
            break;
        }

        memcpy(packet, recv_buf, packet_len);

        // Handle rest of buffer (may contain more data)
        size_t remaining = recv_buf_size - packet_len;
        memmove(recv_buf, newline_ptr + 1, remaining);
        recv_buf_size = remaining;

        // --- Write the received line ---
        if (write_packet_to_file(packet, packet_len) != EXIT_SUCCESS)
        {
            syslog(LOG_ERR, "Failed to write packet to file/device\n");
            free(packet);
            break;
        }
        free(packet);
        packet = NULL;

        // --- Read back and send response ---
        if (read_packet_from_file(&read_buf, &read_len) != EXIT_SUCCESS)
        {
            syslog(LOG_ERR, "Failed to read packet from file/device\n");
            break;
        }

        if (sendall(client_info->client_conn_fd, read_buf, read_len) == -1)
        {
            syslog(LOG_ERR, "Failed to send data to client %s\n", client_info->client_addr_string);
            free(read_buf);
            break;
        }

        syslog(LOG_DEBUG, "Sent %zu bytes back to client %s\n", read_len, client_info->client_addr_string);
        free(read_buf);
        read_buf = NULL;

#if !USE_AESD_CHAR_DEVICE
        // --- Handle leftover (second) packet logic only for file mode ---
        if (recv_buf_size > 0)
        {
            syslog(LOG_DEBUG, "Leftover data detected, processing next packet fragment\n");
            // Process any leftover fragment in next loop iteration
        }
#endif
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
    // Cleanup resources
    close(client_info->client_conn_fd);
    free(recv_buf);

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

            if (write_packet_to_file(buffer, strlen(buffer)) != EXIT_SUCCESS)
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