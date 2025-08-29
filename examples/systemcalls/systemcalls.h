#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>

bool do_system(const char *command);

bool do_exec(int count, ...);

bool do_exec_redirect(const char *outputfile, int count, ...);

bool checkAbsPath(const char *absPath);

bool isProbablyPath(const char* path );

bool isCommandValid(const char*, const char*, const char*);