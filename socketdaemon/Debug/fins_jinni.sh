#!/bin/bash
clear
cd /tmp/fins/
rm mainsocket_channel
mkfifo mainsocket_channel


cd /dev/shm/
rm sem*.*
cd ~/workspace3/FINS-Framework/socketdaemon/Debug
./socketdaemon
