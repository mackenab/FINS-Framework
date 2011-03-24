#!/bin/bash
clear
cd /tmp/fins/
rm *
mkfifo fins_capture
mkfifo fins_inject
cd ~/workspace2/capturer/Debug
sudo ./capturer
