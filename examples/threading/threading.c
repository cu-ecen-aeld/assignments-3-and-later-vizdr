#include "threading.h"

// Optional: use these functions to add debug or error prints to your application
// #define DEBUG_LOG(msg,...)
#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

void* threadfunc(void* thread_param)
{ 
    // TODO: wait, obtain mutex, wait, release mutex as described by thread_data structure
    // hint: use a cast like the one below to obtain thread arguments from your parameter
    //struct thread_data* thread_func_args = (struct thread_data *) thread_param;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    int rc;
    struct thread_data* data = (struct thread_data *) thread_param;
    pthread_t me = pthread_self();
    DEBUG_LOG("I begin to sleep. Thread id:%lu, Time: %ld",  me, tv.tv_usec);
    usleep(data->wait_to_obtain_ms * 1000);

    gettimeofday(&tv, NULL);
    pthread_t me_too = pthread_self();
    DEBUG_LOG("I waked up and try to lock mutex. Thread Id:%lu, Time: %ld",  me_too, tv.tv_usec);

    rc = pthread_mutex_lock(data->mutex);
    if (rc) 
    {
        gettimeofday(&tv, NULL);
        me_too = pthread_self ();
        ERROR_LOG("I returned with failure from mutex lock. Thread Id:%lu, Time: %ld", me_too, tv.tv_usec);
        return thread_param;
    }
    me = pthread_self();
    gettimeofday(&tv, NULL);
    DEBUG_LOG("I begin to sleep again. Thread id:%lu, Time: %ld",  me, tv.tv_usec);
    usleep(data->wait_to_release_ms * 1000);
    me_too = pthread_self();
    gettimeofday(&tv, NULL);
    DEBUG_LOG("I waked up again. Thread id:%lu, Time: %ld",  me_too, tv.tv_usec);

    rc = pthread_mutex_unlock(data->mutex);
    if (rc) 
    {
        ERROR_LOG("I returned with failure from mutex unlock.");
        return thread_param;
    }

    me = pthread_self();
    DEBUG_LOG("threadfunc completed. Thread id:%lu, ", me);
    data->thread_complete_success = true;

    thread_param = (void*) data;
    return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    /**
     * TODO: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */

     struct thread_data* data = (struct thread_data*)malloc(sizeof(struct thread_data));

    if (data == NULL) 
        return false;
    
    data->wait_to_obtain_ms = wait_to_obtain_ms;  
    data->wait_to_release_ms = wait_to_release_ms;
    data->mutex = mutex;
    data->thread_complete_success = false;
    
    int ret = pthread_create(thread, NULL, threadfunc, data);

    if (ret) 
    {
        errno = ret;
        perror("pthread_create");
        free(data);
        exit(EXIT_FAILURE);
    }
    return true;
}

