sudo rmmod -f fins_stack_wedge.ko
sudo insmod fins_stack_wedge.ko
read -p "..."
dmesg > output_dmesg.txt

