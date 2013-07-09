adb shell su -c mkdir /dev/fins
adb push envi_android.cfg /dev/fins/envi.cfg
adb push stack_android.cfg /dev/fins/stack.cfg
adb push drop_tables.sh /dev/fins/drop_tables.sh
adb shell su -c chmod -R 777 /dev/fins
