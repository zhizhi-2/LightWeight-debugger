# 实现调试事件处理
from debugger.my_debugger import *
debugger = Debugger()
pid = input("Enter the PID of the process to attach to: ")
debugger.attach(int(pid))
debugger.run()
# debugger.detach()