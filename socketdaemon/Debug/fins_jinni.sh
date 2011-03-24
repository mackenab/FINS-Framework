#!/bin/bash
clear
cd /tmp/fins/
rm mainsocket_channel
mkfifo mainsocket_channel
cd /dev/shm/
rm sem*.*
cd ~/workspace2/socketdaemon/Debug
./socketdaemon
