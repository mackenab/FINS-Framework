#!/bin/bash
clear
cd /tmp/fins/
rm *
mkfifo fins_capture
mkfifo fins_inject
cd ~/workspace3/FINS-Framework/capturer/Debug
sudo ./capturer
