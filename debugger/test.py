# from debugger.my_debugger import *
#
# # Debugger Shell
# debugger = Debugger()
# prompt = lambda: input(">> ")
#
# pid = input("Enter PID of process to attach to:")
# # Debugger attaches to process OR loads an exe
# debugger.attach(int(pid))
# # # debugger.load("C:\\WINDOWS\\system32\\calc.xe")
# #
# #cmd = prompt()
#
# #Find printf
# printf_addr = debugger.resolve_function_address("msvcrt.dll", "printf")
# print("> Addr of prinf: 0x%016x" % printf_addr)
# print('Set bp at printf? y/n')
# if prompt() == 'y':
#     debugger.get_bp(printf_addr)
#
#     # All bp types tested with find_prinf.py
#
# debugger.run()
#
# # debugger.suspend_all_threads()
# # debugger.process_snapshot(mem_only=False)
# # debugger.resume_all_threads()
# # debugger.detach()
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from debugger.my_debugger import *
from debugger.disassemble import *

debugger = Debugger()
# file_path, file_type = QFileDialog.getOpenFileName(QMainWindow, "打开", "C:/", "All Files(*);;Executable Files(*.exe)")
# print(file_path, file_type)
# mes = debugger.load(file_path)
# print(mes)
# md, code_dump, code_addr = disassemble(file_path)
# for i in md.disasm(code_dump, code_addr):
#     print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
print(debugger.hex_dump("H¹ÿÿÿÿÿÿ"))