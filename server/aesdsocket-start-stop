#!/bin/sh

case "$1" in
    start)
        echo "Start server application with running daemon"
        start-stop-daemon --start --name aesdsocket --startas /usr/bin/aesdsocket -- -d
        ;;

    stop)
        echo "Stop server application with running daemon"
        start-stop-daemon --stop --name aesdsocket
        ;;

    *)
        echo "Usage: $0 {start|stop}"
        exit 1
esac

exit 0