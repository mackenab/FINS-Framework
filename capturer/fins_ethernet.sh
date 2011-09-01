#!/bin/bash
clear
cd /tmp/fins/
rm *
mkfifo fins_capture
mkfifo fins_inject
cd /home/alex/jreed/Pieces/merged/capturer/Debug
sudo ./capturer
