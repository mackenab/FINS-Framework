echo "Blocking UDP traffic to port 5000..."
sleep 1
sudo iptables -F
sudo iptables -A INPUT -p udp --dport 5000 -j DROP
#sudo iptables -A OUTPUT -p udp --dport 5000 -j DROP
#sudo iptables -A FORWARD -p udp --dport 5000 -j DROP
echo "done."

