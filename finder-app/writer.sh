#!/bin/bash

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

if cat <<< $writestr > $writefile; then 
	exit 0
else 
	echo "Failed to create file $1"
	exit 1
fi
 


