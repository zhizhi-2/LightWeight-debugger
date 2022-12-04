from debugger.my_debugger import *
from debugger.structs import *
from capstone import *

kernel32 = windll.kernel32
msvcrt = cdll.msvcrt
debugger = Debugger()

pid = int(input("Enter the pid of the process that you want to attach to: "))
debugger.attach(int(pid))
printf_address = debugger.resolve_function_address("msvcrt.dll", "printf")
print(printf_address)

print('[*] Address of printf: 0x%016x' % printf_address)
addr = str(int(input(">>").upper(), 16))
print(addr)

# 读取8字节的数据
lenght = int(input(">>The lenght you want to read: "))
address_data = debugger.read_process_memory(int(addr), int(lenght))
print(address_data)

md = Cs(CS_ARCH_X86, CS_MODE_64)
for i in md.disasm(address_data, int(addr)):
    print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

data = debugger.dump_process_memory(int(addr),int(lenght))

# debugger.run()
debugger.detach()