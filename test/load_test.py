# # 从调试器本身调用可执行程序
# from debugger.my_debugger import *
# from debugger.structs import *
# debugger = Debugger()
# mes = debugger.load("c:\\Windows\\system32\\calc.exe")
# print(mes)
# # print(debugger.load("C:/Users/zhizhi/Desktop/HelloWorld.exe"))
import win32process
print(win32process.EnumProcesses())