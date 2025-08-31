#!bin/sh

if [ $# -lt 2 ]; then
	echo "Error: number of argumrnts is less then 2. The first arg is directory to search in, the second arg is string to find within the files of the directory"
	exit 1
fi

searchstr=$2
filedir=$1

if [ ! -d $filedir ]; then
	echo -e "Error: $filedir is not a valid directory"
       	exit 1
else
        lines_count=$(grep -r "$searchstr" "$filedir" | wc -l )
	files_count=$(grep -rl "$searchstr" "$filedir" | wc -l)
 	echo "The number of files are $files_count and the number of matching lines are $lines_count"
	exit 0
fi







