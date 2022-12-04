from ctypes.wintypes import *
from debugger.structs import *
# from debugger.memory_snapshot_context import *
# from debugger.memory_snapshot_block import *
# from debugger.pdx import *
import win32process
import sys
import os

kernel32 = windll.kernel32
psapi = windll.psapi      # 进程状态API

# Define prototype param and return types
#kernel32.CreateProcessW.argtype = [DWORD,DWORD,DWORD,DWORD,DWORD,DWORD,DWORD,DWORD,POINTER(STARTUPINFO),POINTER(PROCESS_INFORMATION)]
kernel32.CreateProcessW.restype = BOOL

kernel32.DebugActiveProcess.argtypes = [DWORD]
kernel32.DebugActiveProcess.restype = BOOL

kernel32.WaitForDebugEvent.argtypes = [POINTER(DEBUG_EVENT), DWORD]
kernel32.WaitForDebugEvent.restype = BOOL

kernel32.ContinueDebugEvent.argtypes = [DWORD, DWORD, DWORD]
kernel32.ContinueDebugEvent.restype = BOOL


kernel32.GetThreadContext.argtypes = [HANDLE, POINTER(CONTEXT64)]
kernel32.GetThreadContext.restype = BOOL

kernel32.SetThreadContext.argtypes = [HANDLE, POINTER(CONTEXT64)]
kernel32.SetThreadContext.restype = BOOL


kernel32.OpenProcess.argtypes = [DWORD, BOOL, DWORD64]
kernel32.OpenProcess.restype = HANDLE

kernel32.OpenThread.argtypes = [DWORD, BOOL, DWORD64]
kernel32.OpenThread.restype = HANDLE

kernel32.CloseHandle.argtypes = [HANDLE]
kernel32.CloseHandle.restype = BOOL


kernel32.GetModuleHandleW.argtypes = [LPCWSTR]
kernel32.GetModuleHandleW.restype = HMODULE

kernel32.GetProcAddress.argtypes = [HMODULE, LPCSTR]
kernel32.GetProcAddress.restype = c_void_p


kernel32.ReadProcessMemory.argtypes = [HANDLE, LPCVOID, LPVOID, c_size_t, POINTER(c_size_t)]
kernel32.ReadProcessMemory.restype = BOOL

kernel32.WriteProcessMemory.argtypes = [HANDLE, LPVOID, LPCVOID, c_size_t, POINTER(c_size_t)]
kernel32.WriteProcessMemory.restype = BOOL

kernel32.GetSystemInfo.argtypes = [POINTER(SYSTEM_INFO)]
kernel32.GetSystemInfo.restype = BOOL

kernel32.VirtualQueryEx.argtypes = [HANDLE, LPCVOID, POINTER(MEMORY_BASIC_INFORMATION), SIZE_T]
kernel32.VirtualQueryEx.restype =SIZE_T

kernel32.VirtualProtectEx.argtypes = [HANDLE, LPVOID, SIZE_T, DWORD, POINTER(DWORD)]
kernel32.VirtualProtectEx.restype = BOOL


class Debugger():
    def __init__(self, cs=False):
        self.process_handle = None
        self.pid = None
        self.debugger_active = False
        self.debugger_attached = False
        self.thread_handle = None
        self.context = None
        self.exception = None
        self.exception_address = None
        self.soft_breakpoints = {}
        self.first_breakpoint = True
        self.hardware_breakpoints = {}
        self.single_stepping = False
        # self.breakpoints = {}
        self.peb = None  # process environment block address

        # Get default system page size
        system_info = SYSTEM_INFO()
        kernel32.GetSystemInfo(byref(system_info))
        self.page_size = system_info.dwPageSize
        
        self.guarded_pages = []
        self.memory_breakpoints = {}

        self._log = lambda msg: None  # sys.stderr.write("PDBG_LOG> " + msg + "\n")

        self.client_server = cs  # flag controlling whether or not pydbg is in client/server mode

    def __enter__(self):
        return self
    
    def __exit__(self):
        self.run()
        if self.debugger_attached:
            self.detach()

    def load(self, path_to_exe):
        """
        Launch the specified executable, with debugging access for the
        process.
        """
        creation_flags = DEBUG_PROCESS
        startupinfo = STARTUPINFO()
        process_information = PROCESS_INFORMATION()
        startupinfo.cb = sizeof(startupinfo)


        hProcess, hThread, dwProcessId, dwThreadId = win32process.CreateProcess(
                path_to_exe,
                None,
                None,
                None,
                0,
                win32process.DEBUG_PROCESS,
                None,
                None,
                win32process.STARTUPINFO())
        if dwProcessId:
            self.debugger_active = True
            self.pid = int(dwProcessId)
            self.debugger_attached = True
            self.process_handle = hProcess
            mes = "[*] Successfully launched the process"+f"[*] PID: {dwProcessId}"
        else:
            print(f"[*] Process could not be launched")
            print(f"[*] Error: 0x{get_last_error():016x}")
            print(kernel32.GetLastError())
            mes = f"[*] Process could not be launched"+f"[*] Error: 0x{get_last_error():016x}"

        return mes

    def open_process(self, pid):
        """
        Get a process handle for a given process id (`pid`).
        """
        process_handle = kernel32.OpenProcess(
            PROCESS_ALL_ACCESS,
            False,
            pid
            )
        return process_handle

    def attach(self, pid):
        """
        Attach to active process by process id (`pid`).
        
        Retrieve process handle and acquire debugging access.
        """
        self.process_handle = self.open_process(pid)
        mes = ""
        if kernel32.DebugActiveProcess(pid):
            self.debugger_active = True
            self.pid = int(pid)
            self.debugger_attached = True
            # print(f"[*] Attached to process: {pid}")
            mes = f"[*] Attached to process: {pid}"
            print(mes)
        else:
            # raise SystemExit("[*] Failed to attach debugger to process")
            mes = "[*] Failed to attach debugger to process"
            print(mes)
        return mes

    def run(self):
        """
        Debug loop - one event at a time.
        """
        # self.print_event_code_descriptions()
        while self.debugger_active == True:
            self.get_debug_event()
        # self.debugger_active = False

    def suspend_process(self):
        debug_event = DEBUG_EVENT()
        continue_status = DBG_CONTINUE  # 告诉进程继续执行
        # 3循环调用WaitForDebugEvent()以便俘获调试事件
        if kernel32.WaitForDebugEvent(byref(debug_event), INFINITE):  # DEBUG_EVENT结构描述了一个调试事件，无线等待
            input("Press a key to continue...")
            self.debugger_active = False

        # 4处理函数完成操作后，我们希望进程继续执行调用Continue Debug Event
        kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId,
                                    continue_status)  # continue_status告诉进程继续进行还是产生异常

    def get_debug_event(self):
        """
        Gets next debug event and handle event types.
        Deactivates debugger when process is exited.
        """
        debug_event = DEBUG_EVENT()
        continue_status = DBG_CONTINUE
        bpflag = False
        mes = ""
        if kernel32.WaitForDebugEvent(byref(debug_event), INFINITE):
            # Store thread info
            self.thread_handle = self.open_thread(debug_event.dwThreadId)
            self.context = self.get_thread_context(thread_handle=self.thread_handle)
            
            mes += f"[*] Event code: 0x{debug_event.dwDebugEventCode}   "
            mes += f"Thread ID: {debug_event.dwThreadId}"
            print(f"[*] Event code: 0x{debug_event.dwDebugEventCode}", f"Thread ID: 0x{debug_event.dwThreadId:08x}")
            event_code = debug_event.dwDebugEventCode

            if event_code == EXCEPTION_DEBUG_EVENT:
                mes += "\nException Caught"
                print("Exception Caught")
                exception_record = debug_event.u.Exception.ExceptionRecord
                self.exception = exception_record.ExceptionCode
                self.exception_address = exception_record.ExceptionAddress
            
                if self.exception == EXCEPTION_ACCESS_VIOLATION:
                    mes += "\n[**] Access violation detected"
                    print("[**] Access violation detected")
                    self.dump_registers()
                    self.debugger_active = False  # Process doesn't seem to recover from this

                elif self.exception == EXCEPTION_BREAKPOINT:
                    # mes += "[**] Hit user defined soft breakpoint"
                    # print("[**] Hit user defined soft breakpoint")
                    bpflag = not self.first_breakpoint
                    continue_status, log = self.exception_handler_breakpoint()
                    mes = mes + log

                elif self.exception == EXCEPTION_GUARD_PAGE:
                    mes += "\n[**] Hit memory breakpoint - guard page access detected"
                    print("[**] Hit memory breakpoint - guard page access detected")
                    continue_status = self.exception_handler_guard_page()

                    # System removes guard status for us
                elif self.exception == EXCEPTION_SINGLE_STEP:
                    mes += "\n[**] Hit hardware breakpoint - single stepping"
                    print("[**] Hit hardware breakpoint - single stepping")
                    continue_status, log = self.exception_handler_single_step()
                    mes = mes + log
                    
            elif event_code == EXIT_PROCESS_DEBUG_EVENT:
                mes += "[*] Process exited"
                print("[*] Process exited")
                self.debugger_active = False
        
            kernel32.ContinueDebugEvent(
                debug_event.dwProcessId,
                debug_event.dwThreadId,
                continue_status
            )
            # if it is breakpoint
            # if bpflag == True:
            #     self.write_process_memory(self.exception_address, '\xCC')
        return mes

    def exception_handler_guard_page(self):
        print('[**]Exception address:0x%08x'%self.exception_address)
        return DBG_CONTINUE

    def detach(self):
        """
        Take process out of debug mode.
        """
        if kernel32.DebugActiveProcessStop(self.pid):
            self.debugger_attached = False
            return("[*] Exiting debugger")
            # return True
        else:
            return("[*] There was an error detaching debugger")
            # return False

    def open_thread(self, thread_id):
        """
        Get a thread handle for a given `thread_id`.
        """
        thread_handle = kernel32.OpenThread(
            THREAD_ALL_ACCESS,
            False,
            thread_id
        )
        if thread_handle is not None:
            return thread_handle
        
        print("[*] Could not obtain valid thread handle")
        return False

    def enum_pids(self):
        pids = (DWORD * 1024)()
        size = sizeof(pids)
        return_length = DWORD(1024)
        if not psapi.EnumProcesses(byref(pids), size, byref(return_length)):
            return False
        else:
            # get again with correct size
            c = int(return_length.value / sizeof(DWORD))
            pids = (DWORD * c)()
            size = sizeof(pids)
            return_length = DWORD(1024)
            if not psapi.EnumProcesses(byref(pids), size, byref(return_length)):
                return False
            return pids

    def process_file_name(self, pid):
        ret = False
        h_process = self.open_process(pid)
        if h_process:
            size = 256
            image_file_name = (WCHAR * size)()
            if psapi.GetProcessImageFileNameW(h_process, byref(image_file_name), size):
                ret = os.path.basename(image_file_name.value)
            kernel32.CloseHandle(h_process)
        return ret

    # 枚举进程
    def enum_processes(self):
        processes_info = []
        pids = self.enum_pids()
        for i, pid in enumerate(pids):
            fname = self.process_file_name(pid)
            if fname:
                processes_info.append((pid, fname))
        return processes_info

    # 枚举进程中的模块
    def enum_modules(self):
        module_list = []
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,
                                                     int(self.pid))
        lpme = MODULEENTRY32()
        lpme.dwSize = sizeof(lpme)
        res = kernel32.Module32First(snapshot, byref(lpme))
        i = 1
        while res:
            if lpme.th32ProcessID == int(self.pid):
                module_list.append((lpme.szModule,lpme.szExePath, lpme.modBaseAddr))
                # print("MODULE:", i)
                # print("NAME: ", lpme.szModule)
                # print("PATH: ", lpme.szExePath)
                # print("BASE_ADDRESS:0x{:016X}".format(lpme.modBaseAddr))
            res = kernel32.Module32Next(snapshot, byref(lpme))
            i = i+1
        return module_list

    def enumerate_threads(self):
        """
        Creat a list of thread IDs for children of the proccess that the
        debugger is attached to.
        """
        snapshot = kernel32.CreateToolhelp32Snapshot(
            TH32CS_SNAPTHREAD,
            self.pid
        )
        if snapshot is not None:
            thread_entry = THREADENTRY32()
            thread_entry.dwSize = sizeof(thread_entry)  # Size must be set
            success = kernel32.Thread32First(
                snapshot,
                byref(thread_entry)
            )
        
            thread_list = []
            while success:
                if thread_entry.th32OwnerProcessID == self.pid:
                    thread_list.append(thread_entry.th32ThreadID)
                success = kernel32.Thread32Next(
                    snapshot,
                    byref(thread_entry)
                    )
            # Prevent leaks
            kernel32.CloseHandle(snapshot)
            return thread_list

        print("[*] Could not enumerate threads")
        return False

    def get_thread_context(self, thread_id=None, thread_handle=None):
        """
        Get context object for specified thread ID or context.
        Context contains register info.
        """
        context = CONTEXT64()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS

        if thread_handle is None:
            if thread_id is None:
                print(f"[*] Must provide thread ID or handle to get context")
                return False
            thread_handle = self.open_thread(thread_id)

        if kernel32.GetThreadContext(thread_handle, byref(context)):
            return context
        
        print(f"[*] Could not get context for thread")
        return False

    def set_thread_context(self, context, thread_handle=None):
        if not thread_handle:
            thread_handle = self.thread_handle

        if not kernel32.SetThreadContext(thread_handle, byref(context)):
            return False

        # kernel32.CloseHandle(h_thread)
        return True

    def virtual_protect(self, base_address, size, protection):
        '''
        Convenience wrapper around VirtualProtectEx()
        '''
        # self._log("VirtualProtectEx( , 0x%08x, %d, %08x, ,)" % (base_address, size, protection))
        old_protect = c_ulong(0)
        if not kernel32.VirtualProtectEx(self.process_handle, base_address, size, protection, byref(old_protect)):
            raise pdx("VirtualProtectEx(%08x, %d, %08x)" % (base_address, size, protection), True)

        return old_protect.value

    # 获取进程的基地址
    def get_BaseAddress(self, name):
        # address = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        address = kernel32.GetModuleHandleW(name)
        return address

    def read_process_memory(self, address, length):
        """
        Read `length` bytes from the specified memory `address`.
        """
        read_buffer = create_string_buffer(length)
        read_byte_count = c_size_t(0)

        if not kernel32.ReadProcessMemory(
            self.process_handle,
            address,
            read_buffer,
            length,
            byref(read_byte_count)
        ):
            return False
        else:
            return read_buffer.raw

    def write_process_memory(self, address, data):
        """
        Write `data` to the specified memory `address`.
        """
        write_byte_count = c_size_t(0)
        length = len(data)
        c_data = c_char_p(data[write_byte_count.value:])

        if not kernel32.WriteProcessMemory(
            self.process_handle,
            address,
            c_data,
            length,
            byref(write_byte_count)
        ):
            return False
        else:
            return True

    def dump_process_memory(self, address, length):
        data = self.read_process_memory(address, length)
        data = data.decode("ISO-8859-1")
        str= self.hex_dump(data, address)
        # filename = "dump.txt"
        # with open(filename, 'w') as name:
        #     name.write(str)
        # name.close()
        # print("The memory contents were successfully dumped")
        print(str)
        return str

    def hex_dump(self, data, addr=0, prefix=""):
        '''
        Utility function that converts data into hex dump format.

        @type  data:   Raw Bytes
        @param data:   Raw bytes to view in hex dump
        @type  addr:   DWORD
        @param addr:   (Optional, def=0) Address to start hex offset display from
        @type  prefix: String (Optional, def="")
        @param prefix: String to prefix each line of hex dump with.

        @rtype:  String
        @return: Hex dump of data.
        '''

        dump = prefix
        slice = ""
        # data = str(data)
        for byte in data:
            if addr % 16 == 0:
                dump += " "

                for char in slice:
                    if ord(char) >= 32 and ord(char) <= 126:
                        dump += char
                    else:
                        dump += "."

                # dump += "\n%s%04x: " % (prefix, addr)
                dump += '\n{}{:04x}: '.format(prefix, addr)
                slice = ""

            dump += "%02x " % ord(byte)
            slice += byte
            addr += 1

        remainder = addr % 16

        if remainder != 0:
            dump += "   " * (16 - remainder) + " "

        for char in slice:
            if ord(char) >= 32 and ord(char) <= 126:
                dump += char
            else:
                dump += "."

        return dump + "\n"

    def set_soft_breakpoint(self, address):
        """
        Set a soft breakpoint at the specified memory `address`.
        Replaces a byte with INT3 (halt in operation code), to set a soft
        breakpoint. Stores the original byte in `self.soft_breakpoints`, to be
        reinserted when the breakpoint is hit.
        """
        if address not in self.soft_breakpoints:
            original_byte = self.read_process_memory(address, 1)
            # print(original_byte)
            # Replace with INT3
            if self.write_process_memory(address, b"\xCC"):
                self.soft_breakpoints[address] = original_byte

                print(f"[*] Soft breakpoint set at 0x{address:016x}")
                return f"[*] Soft breakpoint set is at 0x{address:016x}"
            else:
                print("[*] Could not set breakpoint")
                return "[*] Could not set breakpoint"

    def set_hardware_breakpoint(self, address, length, condition):
        """
        Set a hardware breakpoint in all active threads.
        Parameters
        ----------
        address
            location of breakpoint in memory
        length
            length of data item to be monitored. 1, 2 or 4 bytes.
        condition
            when breakpoint should be triggered. HW_ACCESS, HW_EXCECUTE or HW_WRITE.
        """
        mes = ""
        if length not in (1, 2, 4):
            return False
        else:
            length -= 1
        if condition not in (HW_ACCESS, HW_EXECUTE, HW_WRITE):
            return False
        if 0 not in self.hardware_breakpoints:
            available = 0
        elif 1 not in self.hardware_breakpoints:
            available = 1
        elif 2 not in self.hardware_breakpoints:
            available = 2
        elif 3 not in self.hardware_breakpoints:
            available = 3
        else:
            return False
        for thread_id in self.enumerate_threads():
            context64 = self.get_thread_context(thread_id)
            context64.Dr7 |= 1 << (available * 2)
            if available == 0:
                context64.Dr0 = address
            elif available == 1:
                context64.Dr1 = address
            elif available == 2:
                context64.Dr2 = address
            elif available == 3:
                context64.Dr3 = address
            # set condition
            context64.Dr7 |= condition << ((available * 4) + 16)
            # set length
            context64.Dr7 |= length << ((available * 4) + 18)
            # update context
            h_thread = self.open_thread(thread_id)
            if not kernel32.SetThreadContext(h_thread, byref(context64)):
                print('[*] Set thread context error.')
                return '[*] Set thread context error.'

        # update breakpoint list
        self.hardware_breakpoints[available] = (address, length, condition)
        return f"[*] Hardware breakpoint is set at 0x{address:016x}"

    def set_memory_breakpoint(self, address, size):
        mbi = MEMORY_BASIC_INFORMATION()
        # 如果我们的VirtualQueryEx()调用没有返回完整大小的MEMORY_BASIC_INFORMATION，则返回false
        print("address:",address)
        if kernel32.VirtualQueryEx(
            self.process_handle,
            address,
            byref(mbi),
            sizeof(mbi)
        ) < sizeof(mbi):  # Must be full size
            print("111:",kernel32.VirtualQueryEx(
            self.process_handle,
            address,
            byref(mbi),
            sizeof(mbi)
        ) )
            print("sizeof(mi):",sizeof(mbi))
            print("VirtualQueryEx:")
            print(kernel32.GetLastError())
            return "Failed to set memory breakpoint"
        current_page = mbi.BaseAddress
        print(current_page)
        # 我们将对受内存断点影响的所有页面设置权限
        while current_page <= address + size:
            # 将页面添加到列表中;这将把我们的页面与那些由操作系统或被调试进程设置的页面区别开来
            self.guarded_pages.append(current_page)  # So we can identify those we've created

            old_protection = c_ulong(0)

            if not kernel32.VirtualProtectEx(
                self.process_handle,
                current_page,
                size,
                mbi.Protect | PAGE_GUARD,
                byref(old_protection)
            ):
                return "Failed to set memory breakpoint"
            # 将范围增加到默认系统内存页大小
            current_page += self.page_size
        # 将内存断点加入我们的全局列表
        self.memory_breakpoints[address] = (address, size, mbi)
        return "Memory breakpoint was successfully set"

    def exception_handler_breakpoint(self):
        """
        Handle soft breakpoints.
        """
        mes = ""
        if self.exception_address in self.soft_breakpoints:
            # Put this back where it belongs
            self.write_process_memory(
                self.exception_address,
                self.soft_breakpoints[self.exception_address]
            )

            # Reset thread context instruction pointer
            self.context = self.get_thread_context(
                thread_handle=self.thread_handle
            )
            self.context.Rip -= 1

            kernel32.SetThreadContext(self.thread_handle, byref(self.context))

        else:
            if self.first_breakpoint:
                print("[**] Hit Windows driven breakpoint")
                mes = mes+"\n[**] Hit Windows driven breakpoint"
            else:
                print("[**] Hit non-user-defined breakpoint")
                mes = mes + "\n[**] Hit non-user-defined breakpoint"

        print(f"[**] Exception address: 0x{self.exception_address:016x}")
        mes = mes + f"\n[**] Exception address: 0x{self.exception_address:016x}"
        # self.console()
        return DBG_CONTINUE, mes

    def exception_handler_single_step(self):
        """
        Determine if single step occured in reaction to a hardware breakpoint
        and grab the hit breakpoint.

        Should check for BS flag in Dr6, but Windows doesn't propagate this
        down correctly...
        """
        mes = ""
        if self.context == False:
            print('[*] Exception_handler_single_step get context error.')
            mes = mes + "\n[*] Exception_handler_single_step get context error."
        else:
            if self.context.Dr6 & 0x1 and 0 in self.hardware_breakpoints:
                slot = 0
            elif self.context.Dr6 & 0x2 and 1 in self.hardware_breakpoints:
                slot = 1
            elif self.context.Dr6 & 0x4 and 2 in self.hardware_breakpoints:
                slot = 2
            elif self.context.Dr6 & 0x8 and 3 in self.hardware_breakpoints:
                slot = 3
            else:
                continue_status = DBG_EXCEPTION_NOT_HANDLED
            # remove this hardware breakpoint
            if self.delete_hardware_breakpoint(slot):
                continue_status = DBG_CONTINUE
                print('[*] Hardware breakpoint removed.')
                mes = mes + "\n[*] Hardware breakpoint removed."
            else:
                print('[*] Hardware breakpoint remove failed.')
            # raw_input('[*] Press any key to continue.')
            return continue_status, mes

    def delete_hardware_breakpoint(self, slot):
        """
        Disable a hardware breakpoint in all active threads.
        """
        # 为所有活动线程禁用断点
        for thread_id in self.enumerate_threads():
            context = self.get_thread_context(thread_id)
            # 重置符号位去移除断点
            context.Dr7 &= ~(1 << (slot * 2))
            # 把地址归零
            if slot == 0:
                context.Dr0 = 0x00000000
            elif slot == 1:
                context.Dr1 = 0x00000000
            elif slot == 2:
                context.Dr2 = 0x00000000
            elif slot == 3:
                context.Dr3 = 0x00000000
            # 移除条件标志
            context.Dr7 &= ~(3 << ((slot * 4) + 16))
            # 移除长度标志
            context.Dr7 &= ~(3 << ((slot * 4) + 18))
            # 用移除的断点重置线程的上下文
            h_thread = self.open_thread(thread_id)
            kernel32.SetThreadContext(h_thread, byref(context))
        # 从内部列表中移除断点
        del self.hardware_breakpoints[slot]
        return True

    @staticmethod
    def resolve_function_address(dll, function):
        """
        Get the address of a function in the specified dynamic linked library
        (dll - i.e. module).

        Parameters
        ----------
        dll
            name of dll file that function is located in
        function
            name of function
        """
        module_handle = kernel32.GetModuleHandleW(dll)
        # print('[*] Address of printf: 0x%016x' %module_handle)
        function_address = kernel32.GetProcAddress(
            module_handle,
            bytes(function, "utf-8")  # Method requires byte str
            )
        # Don't need to worry about closing module "handle"
        return function_address

    def dump_registers(self):
        """
        Dump 64-bit register contents for each thread that belongs to the
        process.
        """
        thread_list = self.enumerate_threads()

        registers = {
            "RIP": "Rip",
            "RSP": "Rsp",
            "RBP": "Rbp",
            "RAX": "Rax",
            "RBX": "Rbx",
            "RCX": "Rcx",
            "RDX": "Rdx"
        }

        if thread_list:
            for thread_id in thread_list:
                thread_context = self.get_thread_context(thread_id)
                if thread_context:
                    print(f"[*] Dumping registers for thread ID: 0x{thread_id:016x}")
                    for key, value in registers.items():
                        print(f"[**] {key}: 0x{getattr(thread_context, value):016x}")
                    print(f"[*] END DUMP")

    def print_event_code_descriptions(self):
        print(
            """[*] Event codes:
    0x1 - EXCEPTION_DEBUG_EVENT
    0x2 - CREATE_THREAD_DEBUG_EVENT
    0x3 - CREATE_PROCESS_DEBUG_EVENT
    0x4 - EXIT_THREAD_DEBUG_EVENT
    0x5 - EXIT_PROCESS_DEBUG_EVENT
    0x6 - LOAD_DLL_DEBUG_EVENT
    0x7 - UNLOAD_DLL_DEBUG_EVENT
    0x8 - OUTPUT_DEBUG_STRING_EVENT
    0x9 - RIP_EVENT
"""
        )

    def single_step(self, e, thread_handle=None):
        if not thread_handle:
            thread_handle = self.thread_handle

        # context = self.get_thread_context(self.h_thread)
        if e:
            self.single_stepping = True
            # Set Trap Flag in EFlags register
            self.context.EFlags |= EFLAGS_TRAP
        else:
            self.single_stepping = False
            self.context.EFlags &= (0xFFFFFFFFFF ^ EFLAGS_TRAP)

        self.set_thread_context(self.context, thread_handle=thread_handle)

    def print_registers(self):
        thread_context = self.get_thread_context(thread_handle=self.thread_handle)
        print("[*] Dumping registers for thread ID: 0x%08x" % self.thread_handle)
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

    def virtual_query(self, address):
        '''
        Convenience wrapper around VirtualQueryEx().

        @type  address: DWORD
        @param address: Address to query

        @raise pdx: An exception is raised on failure.

        @rtype:  MEMORY_BASIC_INFORMATION
        @return: MEMORY_BASIC_INFORMATION
        '''

        mbi = MEMORY_BASIC_INFORMATION()

        if kernel32.VirtualQueryEx(self.process_handle, address, byref(mbi), sizeof(mbi)) < sizeof(mbi):
            raise pdx("VirtualQueryEx(%08x)" % address, True)

        return mbi

    def smart_dereference(self, address, print_dots=True, hex_dump=False):
        '''
        "Intelligently" discover data behind an address. The address is dereferenced and explored in search of an ASCII
        or Unicode string. In the absense of a string the printable characters are returned with non-printables
        represented as dots (.). The location of the discovered data is returned as well as either "heap", "stack" or
        the name of the module it lies in (global data).

        @type  address:    DWORD
        @param address:    Address to smart dereference
        @type  print_dots: Bool
        @param print_dots: (Optional, def:True) Controls suppression of dot in place of non-printable
        @type  hex_dump:   Bool
        @param hex_dump:   (Optional, def=False) Return a hex dump in the absense of string detection

        @rtype:  String
        @return: String of data discovered behind dereference.
        '''

        try:
            mbi = self.virtual_query(address)
        except:
            return "N/A"

        # if the address doesn't point into writable memory (stack or heap), then bail.
        if not mbi.Protect & PAGE_READWRITE:
            return "N/A"

        # if the address does point to writeable memory, ensure it doesn't sit on the PEB or any of the TEBs.
        if mbi.BaseAddress == self.peb or mbi.BaseAddress in self.tebs.values():
            return "N/A"

        try:
            explored = self.read_process_memory(address, self.STRING_EXPLORATON_BUF_SIZE)
        except:
            return "N/A"

        # determine if the write-able address sits in the stack range.
        if self.is_address_on_stack(address):
            location = "stack"

        # otherwise it could be in a module's global section or on the heap.
        else:
            module = self.addr_to_module(address)

            if module:
                location = "%s.data" % module.szModule

            # if the write-able address is not on the stack or in a module range, then we assume it's on the heap.
            # we *could* walk the heap structures to determine for sure, but it's a slow method and this process of
            # elimination works well enough.
            else:
                location = "heap"

        explored_string = self.get_ascii_string(explored)

        if not explored_string:
            explored_string = self.get_unicode_string(explored)

        if not explored_string and hex_dump:
            explored_string = self.hex_dump(explored)

        if not explored_string:
            explored_string = self.get_printable_string(explored, print_dots)

        if hex_dump:
            return "%s --> %s" % (explored_string, location)
        else:
            return "%s (%s)" % (explored_string, location)

    def dump_context (self, context=None, stack_depth=5, print_dots=True):
        '''
        Return an informational block of text describing the CPU context of the current thread. Information includes:
            - Disassembly at current EIP
            - Register values in hex, decimal and "smart" dereferenced
            - ESP, ESP+4, ESP+8 ... values in hex, decimal and "smart" dereferenced

        @see: dump_context_list()

        @type  context:     Context
        @param context:     (Optional) Current thread context to examine
        @type  stack_depth: Integer
        @param stack_depth: (Optional, def:5) Number of dwords to dereference off of the stack (not including ESP)
        @type  print_dots:  Bool
        @param print_dots:  (Optional, def:True) Controls suppression of dot in place of non-printable

        @rtype:  String
        @return: Information about current thread context.
        '''

        # if the optional current thread context was not supplied, grab it for the current thread.
        if not context:
            context = self.context

        context_list = self.dump_context_list(context, stack_depth, print_dots)

        context_dump  = "CONTEXT DUMP\n"
        context_dump += "  EIP: %08x %s\n" % (context.Eip, context_list["eip"])
        context_dump += "  EAX: %08x (%10d) -> %s\n" % (context.Eax, context.Eax, context_list["eax"])
        context_dump += "  EBX: %08x (%10d) -> %s\n" % (context.Ebx, context.Ebx, context_list["ebx"])
        context_dump += "  ECX: %08x (%10d) -> %s\n" % (context.Ecx, context.Ecx, context_list["ecx"])
        context_dump += "  EDX: %08x (%10d) -> %s\n" % (context.Edx, context.Edx, context_list["edx"])
        context_dump += "  EDI: %08x (%10d) -> %s\n" % (context.Edi, context.Edi, context_list["edi"])
        context_dump += "  ESI: %08x (%10d) -> %s\n" % (context.Esi, context.Esi, context_list["esi"])
        context_dump += "  EBP: %08x (%10d) -> %s\n" % (context.Ebp, context.Ebp, context_list["ebp"])
        context_dump += "  ESP: %08x (%10d) -> %s\n" % (context.Esp, context.Esp, context_list["esp"])

        for offset in range(0, stack_depth + 1):
            context_dump += "  +%02x: %08x (%10d) -> %s\n" %    \
            (                                                   \
                offset * 4,                                     \
                context_list["esp+%02x"%(offset*4)]["value"],   \
                context_list["esp+%02x"%(offset*4)]["value"],   \
                context_list["esp+%02x"%(offset*4)]["desc"]     \
            )

        return context_dump

    def dump_context_list (self, context=None, stack_depth=5, print_dots=True, hex_dump=False):
        '''
        Return an informational list of items describing the CPU context of the current thread. Information includes:
            - Disassembly at current EIP
            - Register values in hex, decimal and "smart" dereferenced
            - ESP, ESP+4, ESP+8 ... values in hex, decimal and "smart" dereferenced

        @see: dump_context()

        @type  context:     Context
        @param context:     (Optional) Current thread context to examine
        @type  stack_depth: Integer
        @param stack_depth: (Optional, def:5) Number of dwords to dereference off of the stack (not including ESP)
        @type  print_dots:  Bool
        @param print_dots:  (Optional, def:True) Controls suppression of dot in place of non-printable
        @type  hex_dump:   Bool
        @param hex_dump:   (Optional, def=False) Return a hex dump in the absense of string detection

        @rtype:  Dictionary
        @return: Dictionary of information about current thread context.
        '''

        # if the optional current thread context was not supplied, grab it for the current thread.
        if not context:
            context = self.context

        context_list = {}

        context_list["eip"] = self.disasm(context.Eip)
        context_list["eax"] = self.smart_dereference(context.Eax, print_dots, hex_dump)
        context_list["ebx"] = self.smart_dereference(context.Ebx, print_dots, hex_dump)
        context_list["ecx"] = self.smart_dereference(context.Ecx, print_dots, hex_dump)
        context_list["edx"] = self.smart_dereference(context.Edx, print_dots, hex_dump)
        context_list["edi"] = self.smart_dereference(context.Edi, print_dots, hex_dump)
        context_list["esi"] = self.smart_dereference(context.Esi, print_dots, hex_dump)
        context_list["ebp"] = self.smart_dereference(context.Ebp, print_dots, hex_dump)
        context_list["esp"] = self.smart_dereference(context.Esp, print_dots, hex_dump)

        for offset in range(0, stack_depth + 1):
            try:
                esp = self.flip_endian_dword(self.read_process_memory(context.Esp + offset * 4, 4))

                context_list["esp+%02x"%(offset*4)]          = {}
                context_list["esp+%02x"%(offset*4)]["value"] = esp
                context_list["esp+%02x"%(offset*4)]["desc"]  = self.smart_dereference(esp, print_dots, hex_dump)
            except:
                context_list["esp+%02x"%(offset*4)]          = {}
                context_list["esp+%02x"%(offset*4)]["value"] = 0
                context_list["esp+%02x"%(offset*4)]["desc"]  = "[INVALID]"

        return context_list

    def process_restore(self):
        '''
        Restore memory / context snapshot of the debuggee. All threads must be suspended before calling this routine.

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        # fetch the current list of threads.
        current_thread_list = self.enumerate_threads()

        # restore the thread context for threads still active.
        for thread_context in self.memory_snapshot_contexts:
            if thread_context.thread_id in current_thread_list:
                self.set_thread_context(thread_context.context, thread_id=thread_context.thread_id)

        # restore all saved memory blocks.
        for memory_block in self.memory_snapshot_blocks:
            try:
                self.write_process_memory(memory_block.mbi.BaseAddress, memory_block.data, memory_block.mbi.RegionSize)
            except pdx as x:
                self._err("-- IGNORING ERROR --")
                self._err("process_restore: " + x.__str__().rstrip("\r\n"))
                pass

        return self.ret_self()

    ####################################################################################################################
    def process_snapshot(self, mem_only=False):
        '''
        Take memory / context snapshot of the debuggee. All threads must be suspended before calling this routine.

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        self._log("taking debuggee snapshot")

        do_not_snapshot = [PAGE_READONLY, PAGE_EXECUTE_READ, PAGE_GUARD, PAGE_NOACCESS]
        cursor = 0

        # reset the internal snapshot data structure lists.
        self.memory_snapshot_blocks = []
        self.memory_snapshot_contexts = []

        if not mem_only:
            # enumerate the running threads and save a copy of their contexts.
            for thread_id in self.enumerate_threads():
                context = self.get_thread_context(None, thread_id)

                self.memory_snapshot_contexts.append(memory_snapshot_context(thread_id, context))

                self._log("saving thread context of thread id: %08x" % thread_id)

        # scan through the entire memory range and save a copy of suitable memory blocks.
        while cursor < 0xFFFFFFFF:
            save_block = True

            try:
                mbi = self.virtual_query(cursor)
            except:
                break

            # do not snapshot blocks of memory that match the following characteristics.
            # XXX - might want to drop the MEM_IMAGE check to accomodate for self modifying code.
            if mbi.State != MEM_COMMIT or mbi.Type == MEM_IMAGE:
                save_block = False

            for has_protection in do_not_snapshot:
                if mbi.Protect & has_protection:
                    save_block = False
                    break

            if save_block:
                self._log("Adding %08x +%d to memory snapsnot." % (mbi.BaseAddress, mbi.RegionSize))

                # read the raw bytes from the memory block.
                data = self.read_process_memory(mbi.BaseAddress, mbi.RegionSize)

                self.memory_snapshot_blocks.append(memory_snapshot_block(mbi, data))

            cursor += mbi.RegionSize

        return self.ret_self()

    def get_bp(self, addr=None):
        if addr is None:
            print('Enter address:')
            addr = input('>> ')
        print('Choose type of bp: 1) software bp 2) hw bp 3) mem bp')
        cmd = int(input('>> '))
        if cmd == 1:
            self.set_soft_breakpoint(addr)
        elif cmd == 2:
            self.set_hardware_breakpoint(addr, 1, HW_EXECUTE)
        elif cmd == 3:
            self.set_memory_breakpoint(addr, 10)
        else:
            print('invalid option, no bp set')

    def console(self):
        print('Enter c to continue,', )
        print('b to set user breakpoint,', )
        print('s to toggle single step,', )
        print('r to print registers,', )
        print('m to read memory,', )
        print('mw to write to memory,', )
        # print 'rw to write to registers',
        print('q to quit')

        while True:
            cmd = input(">> ")
            if cmd == 'c':
                return
            elif cmd == 'b':
                self.get_bp()
            elif cmd == 's':
                self.single_stepping = not self.single_stepping
                print("Single Step:", self.single_stepping)
                self.single_step(self.single_stepping)
            elif cmd == 'r':
                self.print_registers()
            elif cmd == 'm':
                print('Enter address:')
                # addr = hex(input(">> "))
                addr = str(int(input(">> ").upper(), 16))
                print("Enter the length you want to r ead:")
                length = int(input(">> "))  # 读取数据的长度
                print(self.read_process_memory(int(addr), length))
            elif cmd == 'mw':
                print('Enter address:')
                addr = input(">> ")
                print('Data:')
                data = input(">> ")
                self.write_process_memory(addr, data)
            elif cmd == 'rw':
                # self.write_register()
                pass
            elif cmd == 'q':
                self.detach()
                sys.exit()
                return


    def ret_self(self):
        '''
        This convenience routine exists for internal functions to call and transparently return the correct version of
        self. Specifically, an object in normal mode and a moniker when in client/server mode.

        @return: Client / server safe version of self
        '''

        if self.client_server:
            return "**SELF**"
        else:
            return self

    def suspend_all_threads(self):
        '''
        Suspend all process threads.

        @see: resume_all_threads()

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        for thread_id in self.enumerate_threads():
            self.suspend_thread(thread_id)

        return self.ret_self()

    def resume_all_threads(self):
        '''
        Resume all process threads.

        @see: suspend_all_threads()

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        for thread_id in self.enumerate_threads():
            self.resume_thread(thread_id)

        return self.ret_self()

    ####################################################################################################################
    def resume_thread(self, thread_id):
        '''
        Resume the specified thread.

        @type  thread_id: DWORD
        @param thread_id: ID of thread to resume.

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        self._log("resuming thread: %08x" % thread_id)

        thread_handle = self.open_thread(thread_id)

        # if kernel32.ResumeThread(thread_handle) == -1:
            # raise pdx("ResumeThread()", True)

        kernel32.CloseHandle(thread_handle)

        return self.ret_self()

    def suspend_thread(self, thread_id):
        '''
        Suspend the specified thread.

        @type  thread_id: DWORD
        @param thread_id: ID of thread to suspend

        @raise pdx: An exception is raised on failure.
        @rtype:     pydbg
        @return:    Self
        '''

        self._log("suspending thread: %08x" % thread_id)

        thread_handle = self.open_thread(thread_id)

        # if kernel32.SuspendThread(thread_handle) == -1:
        #     raise pdx("SuspendThread()", True)

        kernel32.CloseHandle(thread_handle)

        return self.ret_self()

    def dbg_print_all_debug_registers(self):
        """
        *** DEBUG ROUTINE ***

        This is a debugging routine that was used when debugging hardware breakpoints.
        It was too useful to be removed from the release code.
        """

        # ensure we have an up to date context for the current thread.
        context = self.get_thread_context(self.h_thread)

        print('eip = 0x{:08x}'.format(context.Eip))
        print('Dr0 = 0x{:08x}'.format(context.Dr0))
        print('Dr1 = 0x{:08x}'.format(context.Dr1))
        print('Dr2 = 0x{:08x}'.format(context.Dr2))
        print('Dr3 = 0x{:08x}'.format(context.Dr3))
        print('Dr7 = {!s}'.format(self.to_binary(context.Dr7)))
        print('      10987654321098765432109876543210')
        print('      332222222222111111111')

    def dbg_print_all_guarded_pages(self):
        """
        *** DEBUG ROUTINE ***

        A debugging routine that was used when debugging memory breakpoints.
        It was too useful to be removed from the release code.
        """

        cursor = 0

        # scan through the entire memory range.
        while cursor < 0xFFFFFFFF:
            try:
                mbi = self.virtual_query(cursor)
            except:
                break

            if mbi.Protect & PAGE_GUARD:
                address = mbi.BaseAddress
                print('PAGE GUARD on 0x{:08x}'.format(mbi.BaseAddress))

                while True:
                    address += self.page_size
                    tmp_mbi = self.virtual_query(address)

                    if not tmp_mbi.Protect & PAGE_GUARD:
                        break

                    print('PAGE GUARD on 0x{:08x}'.format(address))

            cursor += mbi.RegionSize