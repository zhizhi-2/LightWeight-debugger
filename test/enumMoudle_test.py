# 枚举模块
from debugger.my_debugger import *

debugger = Debugger()
pid = input("Enter the PID of the process to attach to: ")
debugger.attach(int(pid))
module_list = debugger.enum_modules()
# print(module_list)
for i, (name, path, baseAddress) in enumerate(module_list):
    print("MODULE:", i)
    print("NAME: ", name)
    print("PATH: ", path)
    print("BASE_ADDRESS:0x{:016X}".format(baseAddress))
debugger.detach()

