echo "Flushing UDP iptables rules..."
sleep 1
sudo iptables -F
sudo iptables -A INPUT -p udp -j ACCEPT
sudo iptables -A OUTPUT -p udp -j ACCEPT
sudo iptables -A FORWARD -p udp -j ACCEPT
echo "done."
