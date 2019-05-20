# -*- coding: utf-8 -*-  


for i in range(idaapi.get_nlist_size()):
  name = idaapi.get_nlist_name(i)
  if name.find("_class_type_infoE") == -1:
    continue
  # _ZTVN10__cxxabiv117__class_type_infoE     -> `vtable for'__cxxabiv1::__class_type_info
  # _ZTVN10__cxxabiv120__si_class_type_infoE  -> `vtable for'__cxxabiv1::__si_class_type_info
  # _ZTVN10__cxxabiv121__vmi_class_type_infoE -> `vtable for'__cxxabiv1::__vmi_class_type_info
  for xref in idautils.DataRefsTo(idaapi.get_nlist_ea(i)):
    strLog = True
    xFromList = list(idautils.DataRefsFrom(xref + 4))
    if len(xFromList) != 1:
      print "idautils.DataRefsFrom Failed of %08X" %(xref + 4)
      continue
    idc.MakeUnknown(xFromList[0], 1, DOUNK_SIMPLE | DOUNK_EXPAND | DOUNK_DELNAMES)
    idc.MakeStr(xFromList[0], BADADDR)
    xFromStr = idc.GetString(xFromList[0])
    idc.MakeName(xref, "_ZTI" + xFromStr)
    xToList = list(idautils.DataRefsTo(xref))
    if len(xToList) == 1:
      idc.MakeName(xToList[0]+4, "_ZTV" + xFromStr)
      strLog = False
      continue
    for i in range(len(xToList)):
      xFromList = list(idautils.DataRefsFrom(xToList[i] + 4))
      if len(xFromList) != 1:
        continue
      xName = idaapi.get_visible_name(xFromList[0] & 0xFFFFFFFE)
      if xName.find("sub_") == 0 or xName.find("__imp__") == 0:
        idc.MakeName(xToList[i]+4, "_ZTV" + xFromStr)
        strLog = False
        break
    if strLog:
      print "can't found vtable of _ZTI" + xFromStr
    pass
