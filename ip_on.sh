#!/bin/bash
echo "Flushing iptables rules..."
sleep 1
sudo iptables -F
sudo iptables -P INPUT ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
echo "done."
