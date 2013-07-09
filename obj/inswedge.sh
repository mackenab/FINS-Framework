sudo modprobe -r fins_stack_wedge
sudo modprobe fins_stack_wedge
read -p "..."
#dmesg > output_dmesg.txt
cat /var/log/syslog | grep FINS: > output_dmesg.txt
