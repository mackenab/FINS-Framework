service network-manager stop


#starts the ad hoc server
ifconfig wlan0 down
sleep 1
iwconfig wlan0 mode ad-hoc
sleep 1
iwconfig wlan0 txpower 1.0
sleep 1
iwconfig wlan0 channel 1
sleep 1
iwconfig wlan0 essid 'FINSAdhoc'
sleep 1
ifconfig wlan0 10.42.43.10 netmask 255.255.255.0 broadcast 10.42.43.255
sleep 1
ifconfig wlan0 up
sleep 1
