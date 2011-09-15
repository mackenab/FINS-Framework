#!/bin/bash
echo "Blocking all traffic..."
sleep 1
sudo iptables -F
sudo iptables -P INPUT DROP
sudo iptables -P OUTPUT DROP
sudo iptables -P FORWARD DROP
echo "done."
