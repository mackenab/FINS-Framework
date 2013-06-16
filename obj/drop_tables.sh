if [ "$ANDROID_DATA" == "" ]; then
	echo "Ubuntu"
	sudo iptables -A INPUT -j DROP
	sudo iptables -A OUTPUT -j DROP
	sudo iptables -A FORWARD -j DROP
else
	echo "Android"
	iptables -A INPUT -j DROP
	iptables -A OUTPUT -j DROP
	iptables -A FORWARD -j DROP
fi
