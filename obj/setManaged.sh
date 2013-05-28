service network-manager stop


#starts the Managed mode network
sudo ifconfig wlan0 down
sleep 1
sudo dhclient -r wlan0
sleep 1
sudo ifconfig wlan0 up
sleep 1
sudo iwconfig wlan0 essid "FINSFramework"
sleep 1
sudo iwconfig wlan0 mode Managed
sleep 1
sudo dhclient wlan0
sleep 1
