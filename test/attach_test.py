# 附加到目标进程
from debugger.my_debugger import *
debugger = Debugger()
pid = input("Enter the PID of the process to attach to:")
debugger.attach(int(pid))
debugger.suspend_all_threads()
debugger.detach()