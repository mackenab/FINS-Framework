ps -e | grep client | awk '{print $1;}'| xargs kill -9
ps -e | grep server | awk '{print $1;}'| xargs kill -9
ps -e | grep socketdaemon | awk '{print $1;}'| xargs kill -9
ps -e | grep capturer | awk '{print $1;}'| xargs kill -9
