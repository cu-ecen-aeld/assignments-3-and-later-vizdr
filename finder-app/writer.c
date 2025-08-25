#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>


int main(int argc, char *argv[])
{
    openlog(NULL, 0, LOG_USER);
    const char* path;
    const char* writefile;
    const char* writestr;
    if(argc != 3)
        {
            /* fprintf(stdout, "The expected 2 arguments are not provided. The first argument is: %s, the second: %s", argv[1], argv[2]); */
            syslog(LOG_ERR, "Two arguments expected (path, writestring), but found: %d", argc - 1u);
            return 1u;
        }
    if (argv[1] == NULL)
    {
        syslog(LOG_ERR, "Two arguments expected, but writestring not found: %s", argv[1]);
    }
    
    {
        int fd;        
        path = argv[1];
        writefile = strrchr(path, '/');
        writestr = argv[2];
        /* create file to write, truncate */
        fd = creat (path, 0644);
        if (fd == 1)
        {
            syslog(LOG_ERR, "The file  %s  could not be created", writefile);
            return 1;
        }
        else
        {
            ssize_t nr;
            nr = write(fd, writestr, strlen(writestr));
            syslog(LOG_DEBUG, "Writing %s to %s", writestr, writefile);
            if (close(fd) == -1)
            {
                syslog(LOG_ERR, "The file  %s  could not be closed", writefile);
                return 1;
            };
        }
        return 0u;
    }    
};
