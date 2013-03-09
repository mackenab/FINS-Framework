sudo rmmod -f trunk/execs/wedge/fins_stack_wedge.ko
sudo insmod trunk/execs/wedge/fins_stack_wedge.ko
read -p "..."
dmesg > output.txt

