# -*- coding: utf-8 -*-  

import re
import hashlib



def ReadSO2File(start, size, filename):
  with open(filename, "wb") as fd:
    for i in range(size):
      fd.write(struct.pack("B", idaapi.get_byte(start + i)))
      fd.flush()


#ReadSO2File(0x7C4D2000, 0x3DFE000, "./test.so")

def GetBytes(ea, len):
  ret_bytes = []
  if ea == None or ea == BADADDR:
    return ret_bytes
  for i in range(ea, ea+len):
    ret_bytes.append(idaapi.get_byte(i))
  return ret_bytes

class MyItem:
  def __init__(self, ea):
    self.offset = 0 # 当前指令距离第一条指令的偏移
    self.size = idaapi.decode_insn(ea)
    self.bytes = GetBytes(ea, self.size)
    self.isB = False # 跳转 B 指令
    self.bTo = ""
    self.isCall = False # 调用 BX 或 BLX 指令
    self.callTo = ""
    for xref in XrefsFrom(ea, 0):
      if xref.type == 17:
        self.isCall = True
        self.callTo = idc.GetFunctionName(xref.to)
      elif xref.type == 19:
        self.isB = True
        self.bTo = xref.to

class MyFunction:
  def __init__(self, ea, parsePattern = False):
    self.name = idc.GetFunctionName(ea)
    self.nameDigest = hashlib.md5(self.name).hexdigest()
    self.start = idc.GetFunctionAttr(ea, FUNCATTR_START)
    self.end = idc.GetFunctionAttr(ea, FUNCATTR_END)
    self.size = self.end - self.start
    self.pattern = ""
    self.patternDigest = ""
    if parsePattern:
      self.ParsePattern()

  def ParsePattern(self):
    if self.size > 0xFFFF:
      print "%s function too long: 0x%X" %(self.name, self.size)
      return
    items = self.ReadItems()
    pattern = ""
    for i in range(len(items)):
      item = items[i]
      for j in range(item.size):
        if item.isCall:
          pattern += ".."
        elif item.isB and idc.GetFunctionAttr(item.bTo, FUNCATTR_START) != self.start: # 通过 B 指令跳转到其它函数
          pattern += ".."
        else:
          pattern += "%02X" %(item.bytes[j])
    self.pattern = pattern
    self.patternDigest = hashlib.md5(self.pattern).hexdigest()

  def ReadItems(self):
    items = []
    bytes_num = 0
    for itemEa in FuncItems(self.start):
      item = MyItem(itemEa)
      item.offset = bytes_num
      bytes_num += item.size
      items.append(item)
    return items

  def GetPatternString(self):
    preStr = ""
    for i in range(64):
      if i >= len(self.pattern):
        preStr += "."
      else:
        preStr += self.pattern[i]
    patternString = "%s 00 0000 %04X :0000 %s %s %s" %(preStr, \
      self.size, \
      self.name, \
      "", \
      self.pattern[64 : len(self.pattern)])
    return patternString.strip()

class MyPattern:
  def __init__(self, name="", size=0, pattern=""):
    self.name = name
    self.size = size
    self.pattern = pattern[0 : size*2]
    self.patternDigest = hashlib.md5(self.pattern).hexdigest()

def main1():
  patMaps = {}
  with open("./test.pat", "r") as fd:
    while True:
      strLine = fd.readline()
      if strLine == None or strLine == "":
        break
      strLine = re.sub(r'[\x0d\x0a]', "", strLine) # replace "\r\n" -> ""
      if strLine == "---":
        break
      strLines = re.split(r'[\x20\x09]+', strLine) # split by "\t" or " "
      if len(strLines) < 6:
        continue
      pattern1 = strLines[0]
      pattern2 = ""
      if len(strLines) > 6:
        pattern2 = strLines[6]
      pat = MyPattern(strLines[5], int(strLines[3], 16), pattern1 + pattern2)
      if not patMaps.has_key(pat.patternDigest):
        patMaps[pat.patternDigest] = []
      patMaps[pat.patternDigest].append(pat)

  #for funcEa in [here()]:
  for funcEa in idautils.Functions():
    if idc.GetFunctionName(funcEa).find("sub_") != 0: # filter all functions that are not starting with "sub_"
      continue
    func = MyFunction(funcEa, True)
    if func.size > 0xFFFF: # function size cannot greater that 0xFFFF
      continue
    #for key in patMaps.keys():
    #  print  patMaps[key][0].name, patMaps[key][0].patternDigest, patMaps[key][0].pattern
    if not patMaps.has_key(func.patternDigest):
      continue
    patList = patMaps[func.patternDigest]
    for i in range(len(patList)):
      if patList[i].pattern == func.pattern:
        print func.name, patList[i].name
        if idc.MakeName(func.start, patList[i].name) == False:
          j = 0
          while idc.MakeName(func.start, "%s_%d" %(patList[i].name, j)) == False:
            j += 1
        break

if __name__ == "__main__":
  main1()


