from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from GUI.MainWindow import *
from GUI.getAddress_Dialog import Ui_Dialog_Address
from GUI.showProcess_Dialog import *
from GUI.breakpoint_Dialog import *
from GUI.memory_Dialog import *
from GUI.event_Dialog import *
from GUI.module_Dialog import *
from GUI.transAddress_Dialog import *
from debugger.my_debugger import *
from debugger.disassemble import *
from debugger.constants import *
from debugger.address_translation import *
import sys
import PyQt5.sip


# 地址转换的窗口
class window_transAddress(Ui_Dialog_transAddress, QDialog):
    def __init__(self):
        super(QDialog, self).__init__()
        super(Ui_Dialog_transAddress)
        self.setupUi(self)
        # self.pushButton.clicked.connect(self.trans)
        self.setWindowTitle("内存-文件偏移地址转换")  # 设置窗口标题
        self.setWindowIcon(QtGui.QIcon("./resources/childWindow.png"))  # 设置窗口图标


# 显示调试事件类型的窗口
class window_event(Ui_Dialog_event, QDialog):
    def __init__(self):
        super(QDialog, self).__init__()
        super(Ui_Dialog_event)
        self.setupUi(self)
        self.setWindowTitle("Event")  # 设置窗口标题
        self.setWindowIcon(QtGui.QIcon("./resources/childWindow.png"))  # 设置窗口图标
        self.textBrowser.append("0x1 - EXCEPTION_DEBUG_EVENT")
        self.textBrowser.append("0x2 - CREATE_THREAD_DEBUG_EVENT")
        self.textBrowser.append("0x3 - CREATE_PROCESS_DEBUG_EVENT")
        self.textBrowser.append("0x4 - EXIT_THREAD_DEBUG_EVENT")
        self.textBrowser.append("0x5 - EXIT_PROCESS_DEBUG_EVENT")
        self.textBrowser.append("0x6 - LOAD_DLL_DEBUG_EVENT")
        self.textBrowser.append("0x7 - UNLOAD_DLL_DEBUG_EVENT")
        self.textBrowser.append("0x8 - OUTPUT_DEBUG_STRING_EVENT")
        self.textBrowser.append("0x9 - RIP_EVENT")


# 显示载入模块的窗口
class window_module(Ui_Dialog_Module, QDialog):
    def __init__(self):
        super(QDialog, self).__init__()
        super(Ui_Dialog_Module)
        self.setupUi(self)
        self.setWindowTitle("Module")  # 设置窗口标题
        self.setWindowIcon(QtGui.QIcon("./resources/childWindow.png"))  # 设置窗口图标

        self.model = QStandardItemModel(10, 3)
        # self.list = ["列表项1", "列表项2", "列表项3"]
        self.model.setHorizontalHeaderLabels(['名称', '路径', '基地址'])
        self.tableView.setModel(self.model)

        self.tableView.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.tableView.setSelectionMode(QAbstractItemView.SingleSelection)  # 设置只能选中一行
        self.tableView.setEditTriggers(QTableView.NoEditTriggers)  # 不可编辑
        self.tableView.setSelectionBehavior(QAbstractItemView.SelectRows)  # 设置只有行选中


# 设置断点的对话框
class setBreakponit(Ui_Dialog_breakpoint, QDialog):
    signal_address = QtCore.pyqtSignal(str)

    def __init__(self):
        super(QDialog, self).__init__()
        super(Ui_Dialog_breakpoint)
        self.setupUi(self)
        self.setWindowTitle("Breakpoint")  # 设置窗口标题
        self.setWindowIcon(QtGui.QIcon("./resources/childWindow.png"))  # 设置窗口图标

        self.Button_ok.clicked.connect(self.get_address)

    def get_address(self):
        address = self.lineEdit.text()
        address = str(int(str(address).upper(), 16))
        print("get_addres", address)
        self.signal_address.emit(address)
        self.reject()


# 读取内存数据的对话框
class readMemory(Ui_Dialog_memory, QDialog):
    signal_address = QtCore.pyqtSignal(str)
    signal_length = QtCore.pyqtSignal(int)

    def __init__(self):
        super(QDialog, self).__init__()
        super(Ui_Dialog_memory)
        self.setupUi(self)
        self.setWindowTitle("Memory")  # 设置窗口标题
        self.setWindowIcon(QtGui.QIcon("./resources/childWindow.png"))  # 设置窗口图标

        self.pushButton_ok.clicked.connect(self.get_mes)

    def get_mes(self):
        address = self.lineEdit_address.text()
        address = str(int(str(address).upper(), 16))
        print("get_mea:", address)
        length = self.lineEdit_length.text()
        print("get_length", length)
        self.signal_address.emit(address)
        self.signal_length.emit(length)
        self.reject()


# 该窗口用于显示所有运行的进程
class AllProcess(Ui_showProcess_Dialog, QDialog):
    # 定义信号
    # signal_log = QtCore.pyqtSignal(str)
    signal_pid = QtCore.pyqtSignal(int)

    def __init__(self):
        super(QDialog, self).__init__()
        super(Ui_showProcess_Dialog)
        self.setupUi(self)
        self.setWindowTitle("Process")  # 设置窗口标题
        self.setWindowIcon(QtGui.QIcon("./resources/childWindow.png"))  # 设置窗口图标

        self.model = QStandardItemModel(10, 2)
        self.model.setHorizontalHeaderLabels(['PID', '名称'])
        self.tableView.setModel(self.model)
        self.Button_attach.clicked.connect(self.attachProcess)

        self.tableView.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch) # 根据内容调整列的宽度
        self.tableView.setSelectionMode(QAbstractItemView.SingleSelection)  # 设置只能选中一行
        self.tableView.setEditTriggers(QTableView.NoEditTriggers)  # 不可编辑
        self.tableView.setSelectionBehavior(QAbstractItemView.SelectRows)  # 设置只有行选中
        self.tableView.setSortingEnabled(True)

    def attachProcess(self):
        pid = int(self.lineEdit.text())
        if pid:
            self.signal_pid.emit(pid)
            # self.debugger.detach()
            self.reject()


# 获取特定模块特定函数的地址
class GetAddress(Ui_Dialog_Address, QDialog):
    def __init__(self):
        super(QDialog, self).__init__()
        super(Ui_Dialog_Address)
        self.setupUi(self)
        self.setWindowTitle("GetAddreess")  # 设置窗口标题
        self.setWindowIcon(QtGui.QIcon("./resources/childWindow.png"))  # 设置窗口图标
        self.pushButton_yes.clicked.connect(self.get_address)
        self.debugger = Debugger()

    def get_address(self):
        dll = self.lineEdit_dll.text()
        function = self.lineEdit_function.text()
        address = self.debugger.resolve_function_address(dll,function)
        self.lineEdit_address.setText("0x%x"%address)


# 主窗口
class myWindow(Ui_MainWindow, QMainWindow):
    def __init__(self):
        super(QMainWindow, self).__init__()
        super(Ui_MainWindow, self).__init__()
        self.setupUi(self)
        self.setWindowTitle("Lightweight Debugger")   # 设置窗口标题
        self.setWindowIcon(QtGui.QIcon("./resources/debugger.png"))  # 设置窗口图标
        self.debugger = Debugger()
        self.file_path = "c:\\Windows\\system32\\calc.exe"

        self.action_OpenFile.triggered.connect(self.openFiles)
        self.action_Attach.triggered.connect(self.showAllProcess)
        self.action_Exit.triggered.connect(self.closeWindow)
        self.action_run.triggered.connect(self.run_process)
        self.action_detach.triggered.connect(self.detach_process)
        self.action_SoftBreakpoint.triggered.connect(self.add_SoftBreakpoint)
        self.action_HardBreakpoint.triggered.connect(self.add_HardBreakpoint)
        self.action_MemoryBreakpoint.triggered.connect(self.add_MemBreakpoint)
        self.action_ShowMemory.triggered.connect(self.show_memory)
        self.action_Register.triggered.connect(self.show_register)
        self.action_showEvent.triggered.connect(self.show_event)
        self.action_showModule.triggered.connect(self.show_module)
        self.action_transAddress.triggered.connect(self.show_trans)
        self.action_clear.triggered.connect(self.clear_window)
        self.action_getAddress.triggered.connect(self.show_address)

        # 一定要在主窗口类的初始化函数中对子窗口进行实例化，如果在其他函数中实例化子窗口
        # 可能会出现子窗口闪退的问题
        self.window_process = AllProcess()
        self.window_soft_breakpoint = setBreakponit()
        self.window_hard_breakpoint = setBreakponit()
        self.window_memory_breakpoint = setBreakponit()
        self.window_memory = readMemory()
        self.window_event = window_event()
        self.window_module = window_module()
        self.window_trans = window_transAddress()
        self.window_address = GetAddress()

    def clear_window(self):
        self.textBrowser_log.clear()

    def show_trans(self):
        self.window_trans.lineEdit_RVA.clear()
        self.window_trans.lineEdit_RAW.clear()
        self.window_trans.pushButton.clicked.connect(self.trans)
        self.window_trans.show()
        self.window_trans.exec()

    def trans(self):
        RVA = int(self.window_trans.lineEdit_RVA.text(), 16)
        print("RVA", RVA)
        RAW = trans(self.file_path, RVA)
        print("RAW", RAW)
        # RAW = str(RAW)
        self.window_trans.lineEdit_RAW.setText("0x%x"%RAW)

    def openFiles(self):
        path, file_type = QFileDialog.getOpenFileName(self, "打开", "C:/Windows/system32", "All Files(*);;Executable Files(*.exe)")
        self.file_path = path
        # print(self.file_path)
        # print(file_type)
        if path:
            mes = self.debugger.load(path)
            if mes:
                log = "[*]Executable file runs successfully："+path
                self.textBrowser_log.append(log)
                self.textBrowser_log.append(mes)

            md, code_dump, code_addr = disassemble(path)
            for i in md.disasm(code_dump, code_addr):
                self.textBrowser_disa.append("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
        # else:

    def closeWindow(self):
        self.debugger.detach()
        self.close()

    def showAllProcess(self):
        # self.window_process.showTable()
        self.window_process.lineEdit.clear()
        process_list = self.debugger.enum_processes()
        for i, (pid, name) in enumerate(process_list):
            item1 = QStandardItem(str(pid))
            item2 = QStandardItem(name)
            self.window_process.model.setItem(i, 0, item1)
            self.window_process.model.setItem(i, 1, item2)
        # self.window_process.signal_log.connect(self.get_log)
        self.window_process.signal_pid.connect(self.get_pid)
        self.window_process.show()
        self.window_process.exec()
        # self.window_process.quit()

    def show_event(self):
        self.window_event.show()
        self.window_event.exec()

    def show_module(self):
        module_list = self.debugger.enum_modules()
        for i, (name, path,baseAddress) in enumerate(module_list):
            item1 = QStandardItem(str(name))
            item2 = QStandardItem(str(path))
            item3 = QStandardItem(str("0x{:016X}".format(baseAddress)))
            self.window_module.model.setItem(i, 0, item1)
            self.window_module.model.setItem(i, 1, item2)
            self.window_module.model.setItem(i, 2, item3)
        self.window_module.show()
        self.window_module.exec()

    @pyqtSlot(int)
    def get_pid(self, pid):
        print(pid)
        # self.debugger.pid = pid
        mes = self.debugger.attach(pid)
        self.textBrowser_log.append(mes)
        self.textBrowser_register.clear()
        self.textBrowser_memory.clear()
        self.textBrowser_disa.clear()

    def add_SoftBreakpoint(self):
        self.window_soft_breakpoint.signal_address.connect(self.get_address1)
        self.window_soft_breakpoint.lineEdit.clear()
        self.window_soft_breakpoint.show()
        self.window_soft_breakpoint.exec()

    def add_HardBreakpoint(self):
        self.window_hard_breakpoint.signal_address.connect(self.get_address2)
        self.window_hard_breakpoint.lineEdit.clear()
        self.window_hard_breakpoint.show()
        self.window_hard_breakpoint.exec()

    def add_MemBreakpoint(self):
        self.window_memory_breakpoint.signal_address.connect(self.get_address3)
        self.window_memory_breakpoint.lineEdit.clear()
        self.window_memory_breakpoint.show()
        self.window_memory_breakpoint.exec()

    @pyqtSlot(str)
    def get_address1(self, address):
        print(address)
        mes = self.debugger.set_soft_breakpoint(int(address))
        self.textBrowser_log.append(mes)

    @pyqtSlot(str)
    def get_address2(self, address):
        print(address)
        mes = self.debugger.set_hardware_breakpoint(int(address), 1, HW_EXECUTE)
        self.textBrowser_log.append(mes)

    @pyqtSlot(str)
    def get_address3(self, address):
        print(address)
        mes = self.debugger.set_memory_breakpoint(int(address), 10)
        self.textBrowser_log.append(mes)

    def show_memory(self):
        # self.window_memory.signal_length.connect(self.read_memory)
        self.window_memory.signal_address.connect(self.read_memory)
        self.window_memory.lineEdit_length.clear()
        self.window_memory.lineEdit_address.clear()
        self.window_memory.show()
        self.window_memory.exec()

    def show_address(self):
        self.window_address.lineEdit_dll.clear()
        self.window_address.lineEdit_function.clear()
        self.window_address.lineEdit_address.clear()
        self.window_address.show()
        self.window_address.exec()

    @pyqtSlot(str)
    def read_memory(self, address):
        self.textBrowser_disa.clear()
        self.textBrowser_memory.clear()
        length = self.window_memory.lineEdit_length.text()
        address_data = self.debugger.read_process_memory(int(address), int(length))
        if address_data:
            data = self.debugger.dump_process_memory(int(address), int(length))
            self.textBrowser_memory.append(data)
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            for i in md.disasm(address_data, int(address)):
                self.textBrowser_disa.append("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
            self.window_memory.reject()
        else:
            self.textBrowser_log.append("Failed to read memory data")
            self.window_memory.reject()

    def run_process(self):
        if self.debugger.debugger_active == True:
            self.textBrowser_log.append(self.debugger.get_debug_event())

    def detach_process(self):
        log = self.debugger.detach()
        self.textBrowser_log.append(log)




    def show_register(self):
        self.textBrowser_register.clear()
        list = self.debugger.enumerate_threads()
        for thread in list:
            thread_context = self.debugger.get_thread_context(thread)
            self.textBrowser_register.append("[*] Dumping registers for thread ID: %d " %thread)
            self.textBrowser_register.append("[RIP]0x{:016X}".format(thread_context.Rip))
            self.textBrowser_register.append("[RAX]0x{:016X}".format(thread_context.Rax))
            self.textBrowser_register.append("[RCX]0x{:016X}".format(thread_context.Rcx))
            self.textBrowser_register.append("[RDX]0x{:016X}".format(thread_context.Rdx))
            self.textBrowser_register.append("[RBX]0x{:016X}".format(thread_context.Rbx))
            self.textBrowser_register.append("[RSP]0x{:016X}".format(thread_context.Rsp))
            self.textBrowser_register.append("[RBP]0x{:016X}".format(thread_context.Rbp))
            self.textBrowser_register.append("[RSI]0x{:016X}".format(thread_context.Rsi))
            self.textBrowser_register.append("[RDI]0x{:016X}".format(thread_context.Rdi))
            self.textBrowser_register.append("[DR0]0x{:016X}".format(thread_context.Dr0))
            self.textBrowser_register.append("[DR1]0x{:016X}".format(thread_context.Dr1))
            self.textBrowser_register.append("[DR2]0x{:016X}".format(thread_context.Dr2))
            self.textBrowser_register.append("[DR3]0x{:016X}".format(thread_context.Dr3))
            self.textBrowser_register.append("[DR6]0x{:016X}".format(thread_context.Dr6))
            self.textBrowser_register.append("[DR7]0x{:016X}".format(thread_context.Dr7))
            self.textBrowser_register.append("[*] END DUMP")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    w = myWindow()
    w.show()
    sys.exit(app.exec())