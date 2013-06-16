adb shell su -c mkdir /data/local/fins
adb push envi_android.cfg /data/local/fins/envi.cfg
adb push stack_android.cfg /data/local/fins/stack.cfg
adb push drop_tables.sh /data/local/fins/drop_tables.sh
adb shell su -c chmod -R 777 /data/local/fins
