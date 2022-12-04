import pefile


def trans(file_path, rva):
    pe = pefile.PE(file_path)
    # print(pe)
    section_count = pe.FILE_HEADER.NumberOfSections                                 # 区块的个数
    # print(section_count)
    memory_alignment = pe.OPTIONAL_HEADER.SectionAlignment                         # 内存对齐大小
    # print(memory_alignment)
    raw = pe.get_offset_from_rva(rva)
    # print("rva:", rva)
    # print("raw:", raw)
    # print("0x%x" %raw)
    return raw


# raw = trans("c:\\Windows\\system32\\calc.exe", 0x1012)
# print("0x%x"%raw)
# trans("C:\\Users\\zhizhi\\Desktop\\HelloWorld.exe", 0x3330)