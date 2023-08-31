
from idaapi import set_item_color

file_path = "log_1D5928.txt"  # 指令文件路径
addresses = []  # 存储提取出的地址

# 打开文件进行读取
with open(file_path, "r") as file:
    for line in file:
        instruction = line.strip()  # 去除每行指令前后的空白字符
        address = instruction.split()[0]  # 使用split()函数提取指令地址
        if address.startswith("0x"):
            addresses.append(address)  # 将地址添加到列表中

# print(addresses)  # 输出: ['0x1d307c', '0x2a4030', ...]

for i in range(len(addresses)):
    set_item_color(int(addresses[i], 16), 0x98FB98) # 设置地址背景色为绿色
    # idaapi.set_item_color(0x1D31F4, idc.DEFCOLOR) # 还原背景色
