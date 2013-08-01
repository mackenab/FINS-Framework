adb shell su -c mkdir /sdcard/fins
adb push envi_android.cfg /sdcard/fins/envi.cfg
adb push stack_android.cfg /sdcard/fins/stack.cfg
adb shell su -c chmod -R 777 /sdcard/fins
adb shell su -c mkdir /data/local/fins
adb push drop_tables.sh /data/local/fins/drop_tables.sh
adb shell su -c chmod -R 777 /data/local/fins
