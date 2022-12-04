# 断点测试
from debugger.my_debugger import *
from debugger.structs import *

kernel32 = windll.kernel32
msvcrt = cdll.msvcrt
debugger = Debugger()

pid = int(input("Enter the pid of the process that you want to attach to:"))
debugger.attach(int(pid))
printf_address = debugger.resolve_function_address("msvcrt.dll", "printf")
print('[*] Address of printf: 0x%016x' % printf_address)

# debugger.set_soft_breakpoint(printf_address)     # 软件断点
#debugger.set_hardware_breakpoint(printf_address, 1, HW_EXECUTE)    # 硬件断点
debugger.set_memory_breakpoint(printf_address, 10)        # 内存断点
# print(a)
# b = debugger.dbg_print_all_guarded_pages()
# print(b)

debugger.run()

debugger.detach()
