# -*- coding: utf-8 -*-  

import hashlib

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
      #print xref.type, XrefTypeName(xref.type), 'from', hex(xref.frm), 'to', hex(xref.to)
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

  def ReadItems(self):
    items = []
    bytes_num = 0
    for itemEa in FuncItems(self.start):
      item = MyItem(itemEa)
      item.offset = bytes_num
      bytes_num += item.size
      items.append(item)
    return items

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

def main1():
  namesDigest = {}
  patsDigest = {}

  # 遍历所有已定义的函数
  for funcEa in idautils.Functions():
    if SegName(funcEa) != ".text": # 只遍历 .text 段的函数
      continue
    if idc.GetFunctionName(funcEa).find("sub") == 0 \
      or idc.GetFunctionName(funcEa).find("nullsub") == 0 \
      or idc.GetFunctionName(funcEa).find("__") == 0 \
      or idc.GetFunctionName(funcEa).find("j_") == 0: # 过滤 sub 开头的函数
      continue
    #print "0x%04X: %s" %(idc.GetFunctionAttr(funcEa, FUNCATTR_END) - idc.GetFunctionAttr(funcEa, FUNCATTR_START), idc.GetFunctionName(funcEa))
    #continue
    func = MyFunction(funcEa, True)
    if func.size > 0xFFFF: # 函数大小不能大于 0xFFFF
      continue
    if not patsDigest.has_key(func.patternDigest):
      patsDigest[func.patternDigest] = []
    patsDigest[func.patternDigest].append(func.nameDigest)
    if namesDigest.has_key(func.nameDigest):
      raise ValueError("the function name is not unique! name: %s MD5 Digest: %s" %(func.name, func.nameDigest))
    namesDigest[func.nameDigest] = func

  for patDigest in patsDigest.keys():
    namesDigestList = patsDigest[patDigest]
    if len(namesDigestList) > 1:
      print "exists pattern: %s" %(namesDigest[namesDigestList[0]].pattern)
      for i in range(len(namesDigestList)):
        nameDigest = namesDigestList[i]
        if not namesDigest.has_key(nameDigest):
          print "not found: %s" %(nameDigest)
          continue
        func = namesDigest.pop(nameDigest)
        print func.name

  with open("./test.pat", "w") as fd:
    for i in namesDigest.keys():
      fd.write(namesDigest[i].GetPatternString() + "\r\n")

if __name__ == "__main__":
  print MyFunction(here(), True).GetPatternString()
  #main1()

