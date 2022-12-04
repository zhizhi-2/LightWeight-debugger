from debugger.my_debugger import *
from debugger.structs import *

debugger = Debugger()
pid = input("Enter the PID of the process to attach to: ")
debugger.attach(int(pid))
address = debugger.resolve_function_address("msvcrt.dll", "printf")
length = input("Enter the length you want to dump: ")
data = debugger.dump_process_memory(address, int(length))
print(data)
debugger.detach()
