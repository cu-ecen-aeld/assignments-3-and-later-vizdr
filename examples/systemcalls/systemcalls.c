#include "systemcalls.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>


/**
 * @param cmd the command to execute with system()
 * @return true if the command in @param cmd was executed
 *   successfully using the system() call, false if an error occurred,
 *   either in invocation of the system() call, or if a non-zero return
 *   value was returned by the command issued in @param cmd.
*/
bool do_system(const char *cmd)
{

/*
 * TODO  add your code here
 *  Call the system() function with the command set in the cmd
 *   and return a boolean true if the system() call completed with success
 *   or false() if it returned a failure
*/
    int ret = -1;
    ret = system(cmd);
    if (ret != 0)
    {
        perror("Error: system() call returned nonzero");
        printf("system() call susucceded for command: %s\n\n", cmd);
    }    
    return ret == 0u ;
}

/**
* @param count -The numbers of variables passed to the function. The variables are command to execute.
*   followed by arguments to pass to the command
*   Since exec() does not perform path expansion, the command to execute needs
*   to be an absolute path.
* @param ... - A list of 1 or more arguments after the @param count argument.
*   The first is always the full path to the command to execute with execv()
*   The remaining arguments are a list of arguments to pass to the command in execv()
* @return true if the command @param ... with arguments @param arguments were executed successfully
*   using the execv() call, false if an error occurred, either in invocation of the
*   fork, waitpid, or execv() command, or if a non-zero return value was returned
*   by the command issued in @param arguments with the specified arguments.
*/

bool do_exec(int count, ...)
{
    fflush(stdout);
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;
    
/*
 * TODO:
 *   Execute a system command by calling fork, execv(),
 *   and wait instead of system (see LSP page 161).
 *   Use the command[0] as the full path to the command to execute
 *   (first argument to execv), and use the remaining arguments
 *   as second argument to the execv() command.
 *
*/
    const char * cmd_abs_path = command[0];

    if ( !isCommandValid(command[0], command[1], command[2]) )
    {
        printf("The resulted Command is not valid");
        return false;
    }
   
    int status;
    pid_t pid;
    pid_t child_pid = -1;
    pid_t child_finished; 

    pid = fork();

    if (pid == -1)
    {
        perror("fork() failed ");
        exit(1);
        return false;
    }       
    else if (pid != 0) 
    {
        printf("we are in the parent process of fork() with pid %d, parent pid  %d\n", getpid(), getppid());

        child_finished = wait(&status);

        if(child_finished == -1)
        {
            perror ("failed waitpid");
            return false;
        }
        else
        {
            printf ("finished child pid=%d\n", child_finished);
            if (WIFEXITED (status))
            {
                printf ("Normal termination with exit status=%d\n\n", WEXITSTATUS (status));             
            }
            else if (WIFSIGNALED (status))
            {
                printf ("Killed by signal=%d%s\n", WTERMSIG (status), WCOREDUMP (status) ? " (dumped core)" : ""); 
            }                                    
        }        
    }
    else 
    {
        child_pid = getpid();
        printf("child process %d in fun do_exec is launched with fork(), parent pid: %d \n", child_pid, getppid());
        printf("child process launches %s\n", cmd_abs_path);

        char * const exexv_args[] = {command[0], command[1], command[2], NULL};
        char * const* resArgStr = exexv_args;
        for(int i=0; i < sizeof(resArgStr); i++)
        {
            printf("exexv_args[%d]: %s\n",i, resArgStr[i]);
        } 

        execv(cmd_abs_path, resArgStr);
        perror("error in execv");  // we are here only in case of error  
        return false;        
    }
    va_end(args);

    return true;
}

/**
* @param outputfile - The full path to the file to write with command output.
*   This file will be closed at completion of the function call.
* All other parameters, see do_exec above
*/
bool do_exec_redirect(const char *outputfile, int count, ...)
{
    fflush(stdout);
    
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;
    // this line is to avoid a compile warning before your implementation is complete
    // and may be removed
    // command[count] = command[count];

/*
 * TODO
 *   Call execv, but first using https://stackoverflow.com/a/13784315/1446624 as a refernce,
 *   redirect standard out to a file specified by outputfile.
 *   The rest of the behaviour is same as do_exec()
 *
*/
    const char * cmd_abs_path = command[0];
    
    if ( !isCommandValid(command[0], command[1], command[2]) )
    {
        printf( "The resulted Command is not valid\n");
        return false;
    }       
    
    int fd = 0;
        if(outputfile)
        {
            fd = open(outputfile, O_WRONLY|O_TRUNC|O_CREAT, 0644);
            if (fd < 0)
            {
                perror("output file could not be created");
                return false;
            }
            printf("Current process pid:%d. Output file %s created in fun do_exec_redirect\n",getpid(), outputfile);
      
        }
    int status;  
    pid_t pid;
    pid_t child_finished;

    pid = fork();

    if (pid == -1)
    {
        perror("fork() failed ");
        exit(-1);
        return false;
    }       
    else if (pid != 0 ) 
    {
        printf("we are in the parent process of fork() returned pid: %d, in fun do_exec_redirect with pid %d, parent pid  %d\n",pid, getpid(), getppid());

        child_finished = wait(&status);

        if(child_finished == -1)
        {
            perror ("failed waitpid");
            return false;
        }
        else
        {
            printf ("finished child pid=%d\n", child_finished);
            close(fd);
            printf("Output file %s closed\n", outputfile);
            if (WIFEXITED (status))
            {
                printf ("Normal termination with exit status=%d\n\n", WEXITSTATUS (status));             
            }
            else if (WIFSIGNALED (status))
            {
                printf ("Killed by signal=%d%s\n", WTERMSIG (status), WCOREDUMP (status) ? " (dumped core)" : ""); 
            }                                    
        }        
    }
    else
    {
        if (dup2(fd, STDOUT_FILENO) == -1)
        {
            perror("redirection with dup2 failed");
            return false;
        }  
            
        char * const exexv_args[] = {command[0], command[1], command[2], NULL};
        char * const* resArgStr = exexv_args;
     
        execv(cmd_abs_path, resArgStr);
        perror("error in execv");  // we are here only in case of error  
        return false;
    }

    if (fcntl(fd, F_GETFD) == -1 && (errno == EBADF))
    {
        perror("outputfile failure");
        return false;
    }
    

    va_end(args);

    return true;
}

bool checkAbsPath(const char *absPath)
{
    struct stat path_stat;
    if (stat(absPath, &path_stat) != 0) 
    {
        printf("The abs. path from arg: %s, for launch does not exist.\n",  absPath);
        return false;  // error (e.g., path does not exist)
    }
    else
    {
        if(S_ISDIR(path_stat.st_mode))
        {
            printf("The abs. path from arg: %s, for launch  is a directory. \n", absPath);
            return false;
        }
        else if(S_ISREG(path_stat.st_mode))
        {
            printf("The abs. path from arg: %s, for launch execv \n", absPath);
        }
        else
        {
             printf("The abs. path from arg: %s, for launch is not a regular file.\n", absPath);
             return false;
        }
    }
    return true;
}

bool isProbablyPath(const char *path)
{
    if( path == NULL || *path == '\0' )
    {
        return false;
    }
    if (path[0] == '/')
    {
        return true;
    }
    if (strchr(path, '/'))
    {
        return true;
    }  
    return false;
}

bool isCommandValid(const char * command0, const char * command1, const char * command2)
{
    printf("Current process pid: %d.\n", getpid());
    if( !(checkAbsPath(command0)) )
    {
        printf("Absolute path for command or arg is not valid: %s, and arg1: %s, arg2: %s, in fun do_exec_redirect\n",  command0, command1, command2);
        return false;  
    }

    if( isProbablyPath(command1) || command2 )
    {
        printf("One of the arguments looks like a path. We check it:\n");
        if( !(checkAbsPath(command1) || checkAbsPath(command2)) )
        {
            printf("One of arguments looks like a path, but is not absolute path: %s, %s\n", command1, command2);
            return false;
        }
    }
    return true;
}
