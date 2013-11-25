IPADDRESS=$1
AP=$2
IPADDRESS=192.168.1.13

sudo modprobe -r b43
#sleep 3
sudo service network-manager stop


#cd /home/fins1/Desktop/workshop/Driver
#sudo make install
sudo modprobe b43
sleep 3
##starts the Managed mode network
##sudo ifconfig wlan0 down
##sleep 1
##sudo dhclient -r wlan0
sudo ifconfig wlan0 up
sleep 1
#sudo iwconfig wlan0 essid $AP
#sudo iwconfig wlan0 essid FINSFramework
#sudo iwconfig wlan0 essid G3P7R
sudo iwconfig wlan0 essid G3P7R_2GEXT
sleep 1
sudo iwconfig wlan0 mode Managed
sleep 1
##sudo dhclient wlan0
sudo ifconfig wlan0 $IPADDRESS netmask 255.255.255.0 up
sleep 1
