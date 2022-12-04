# get_cpu_reg_value.py
# 获取CPU寄存器的状态
from debugger.my_debugger import *
debugger = Debugger()
pid = input("Enter the PID of the process to attach to: ")
debugger.attach(int(pid))
list = debugger.enumerate_threads()
for thread in list:
    thread_context = debugger.get_thread_context(thread)
    print("[*] Dumping registers for thread ID: 0x%08x" % thread)
    print("[RIP]0x{:016X}".format(thread_context.Rip))
    print("[RAX]0x{:016X}".format(thread_context.Rax))
    print("[RCX]0x{:016X}".format(thread_context.Rcx))
    print("[RDX]0x{:016X}".format(thread_context.Rdx))
    print("[RBX]0x{:016X}".format(thread_context.Rbx))
    print("[RSP]0x{:016X}".format(thread_context.Rsp))
    print("[RBP]0x{:016X}".format(thread_context.Rbp))
    print("[RSI]0x{:016X}".format(thread_context.Rsi))
    print("[RDI]0x{:016X}".format(thread_context.Rdi))
    print("[*] END DUMP")
debugger.detach()
