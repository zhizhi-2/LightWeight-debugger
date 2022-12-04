from ctypes import *
from ctypes import wintypes

# Map Microsoft types to ctypes
BYTE = c_ubyte
WORD = c_ushort
DWORD = c_ulong
DWORD64 = c_ulonglong
LPBYTE = POINTER(c_ubyte)
LPTSTR = POINTER(c_char)
HANDLE = c_void_p
PVOID = c_void_p
LPVOID = c_void_p
UINT_PTR = c_ulong
SIZE_T = c_ulong
CHAR = c_char
HMODULE = wintypes.HMODULE
TCHAR = wintypes.CHAR
WCHAR = wintypes.WCHAR
