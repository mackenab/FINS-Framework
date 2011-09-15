echo "Blocking UDP traffic..."
sleep 1
sudo iptables -F
sudo iptables -A INPUT -p udp -j DROP
sudo iptables -A OUTPUT -p udp -j DROP
sudo iptables -A FORWARD -p udp -j DROP
echo "done."

