#!/bin/sh

if [ $# -lt 2 ]; then
	echo "Error: number of arguments is less than 2"
	exit 1
fi

writefile=$1
writestr=$2
dir=$(dirname "$writefile")
echo "$dir"

if [ ! -d $dir ]; then
       mkdir -p $dir
fi

# we write string to file. it overwrites existing file
echo "$writestr" > "$writefile"

# we check success by exit code ($?)
if [ $? -ne 0 ]; then
    echo "Error: file could not be created."
    exit 1
fi
 


