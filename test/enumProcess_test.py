from debugger.my_debugger import *

debugger = Debugger()
process_list = debugger.enum_processes()
for i, (pid, fname) in enumerate(process_list):
    print(i, pid, fname)