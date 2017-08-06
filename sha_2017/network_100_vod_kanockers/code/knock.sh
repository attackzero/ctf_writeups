#!/bin/bash
# Usage: knock.sh <host> <knock sequence>

# The host is the first argument
HOST=$1

# Move the argument list to the left (now the first port to knock becomes the
# first argument)
shift

# For each port in the argument list, connect to it
for PORT in "$@"
do
	nmap -Pn $HOST --max-retries 0 -p $PORT
done
