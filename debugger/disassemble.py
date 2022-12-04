import pefile
from capstone import *


def disassemble(file_path):
    # pid = int(input("Enter the pid of the process that you want to attach to: "))
    # debugger.attach(int(pid))

    pe = pefile.PE(file_path)
    eop = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    code_section = pe.get_section_by_rva(eop)
    code_dump = code_section.get_data()
    code_addr = pe.OPTIONAL_HEADER.ImageBase + code_section.VirtualAddress
    # print("0x%x"%pe.OPTIONAL_HEADER.ImageBase)
    # print(code_addr)
    md = Cs(CS_ARCH_X86, CS_MODE_32)

    # for i in md.disasm(code_dump, code_addr):
    #     print("0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
    return [md, code_dump, code_addr]

# disassemble("c:\\Windows\\system32\\calc.exe")
# disassemble("D:\\Reverse engineering\\核心原理 ，逆向工程（源代码）\\01\\01\\bin\\HelloWorld.exe")
# disassemble()




