# -*- coding: utf-8 -*-  

import re
import hashlib
from ctypes import cdll
import struct


#filters = {}
#with open("C:\\Users\\Administrator\\Desktop\\className.txt", "r") as fd:
#  curLine = fd.readline().replace("\n", "")
#  while curLine != "":
#    filters[curLine] = 1
#    curLine = fd.readline().replace("\n", "")
#for key in filters.keys():
#  print key


__DecodeClassName_DLL = None
if __DecodeClassName_DLL == None:
  __DecodeClassName_DLL = cdll.LoadLibrary("C:\\Users\\Administrator\\Desktop\\MyDecode\\MyDecode\\x64\\Release\\MyDecode.dll")

# 1. undefine 目标地址
# 2. 目标地址定义为字节数组
# 3. 从目标位置读指定数量的字节序列
# 4. 解密字节序列
# 5. 重命名目标位置
def DecodeClassName(addr, size):
  buf = ""
  for i in range(size):
    buf += struct.pack("B", idaapi.get_byte(addr + i))
  __DecodeClassName_DLL.DecodeClassName(buf, len(buf))
  idc.MakeUnknown(addr, size+1, DOUNK_SIMPLE | DOUNK_EXPAND | DOUNK_DELNAMES) # 快捷键 'U'
  idc.MakeArray(addr, size+1) # 快捷键 '*'
  j = 0
  name = "g_%s_EncodeStr" %buf.replace("::", "__")
  while idc.MakeName(addr, name) == False:
    j += 1
    name = "g_%s_EncodeStr_%02d" %(buf.replace("::", "__"), j)
    if j > 20:
      break



def test():
  unknown = []
  i = 0
  ea = 0x921764FC
  for xref in XrefsTo(ea, 0):
  #if 1:
  #  xref.frm = here()
    # 用换行符 '\n' 分割反编译字符串, 然后遍历每一行.
    lines = []
    try:
      lines = str(idaapi.decompile(xref.frm)).split("\n")
    except:
      unknown.append(xref.frm)

    for i in range(len(lines)):
      if lines[i].find("decodeClassName") != -1:
        # 获得decodeClassName函数的上一行
        prevLine = lines[i-1]
        # 判断上一行是否JByteArray构造, 如果不是则放弃这个函数
        if prevLine.find("JByteArray::JByteArray") != -1:
          param2 = prevLine[prevLine.find(",") + 2 : prevLine.rfind(",")]
          size = prevLine[prevLine.find(param2) + len(param2) + 2 : len(prevLine) - 2] # 字符串分割, 获得构造函数的第三个参数: 数组长度
          addr = param2[param2.find("_") + 1 : len(param2)] # 字符串分割, 获得构造函数的第二个参数: 数组首地址
          if addr.find("+") != -1:
            print addr
            left = addr[0 : addr.find("+") - 1]
            right = addr[addr.find("+") + 2 : len(addr)]
          else:
            left = addr
            right = "0"
          try:
            addr = int(left, 16) + int(right)
          except:
            addr = -1
            #print "%08X" %xref.frm
            unknown.append(xref.frm)
          if addr == -1:
            break
          DecodeClassName(addr, int(size))
        break
  #for i in range(len(unknown)):
  #  print "%08X" %unknown[i]

test()
