import time
import frida

# 连接安卓机上的frida-server
device = frida.get_usb_device()
# 启动`demo02`这个app
# pid = device.spawn(["com.tencent.mm"])
# device.resume(pid)
# time.sleep(25)
session = device.attach(13155)
# 加载s1.js脚本
with open("test.js") as f:
    script = session.create_script(f.read())
script.load()

# 脚本会持续运行等待输入
input()
