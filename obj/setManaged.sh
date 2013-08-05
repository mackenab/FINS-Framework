IPADDRESS=$1
AP=$2

#sudo modprobe -r b43
sleep 3
sudo service network-manager stop


#cd ./Driver
#sudo make install
#sudo modprobe b43
#sleep 3
#starts the Managed mode network
#sudo ifconfig wlan0 down
#sleep 1
#sudo dhclient -r wlan0
sudo ifconfig wlan0 up
sleep 1
#sudo iwconfig wlan0 essid $AP
sudo iwconfig wlan0 essid FINSFramework
sleep 1
sudo iwconfig wlan0 mode Managed
sleep 1
#sudo dhclient wlan0
sudo ifconfig wlan0 $IPADDRESS netmask 255.255.255.0 up
sleep 1
