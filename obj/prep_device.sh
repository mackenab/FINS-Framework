adb shell su -c mkdir /data/local/fins
#adb shell su -c touch /data/local/fins/fins_capture
#adb shell su -c touch /data/local/fins/fins_inject
#adb shell su -c touch /data/local/fins/fins_rtm
adb shell su -c chmod -R 777 /data/local/fins
adb push envi_android.cfg /data/local/fins/envi.cfg
adb push stack_android.cfg /data/local/fins/stack.cfg
