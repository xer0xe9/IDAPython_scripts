import json
import idc
import idautils

exports = {}
f = open('exports.json', 'r')
exports = json.load(f)


def resolve_CRC32Hash(xrefs_to):
    libHashDict = {}
    for addr in xrefs_to:
        if idc.GetOpType(idc.PrevHead(addr),1) == 5:
           hash = idc.GetOpnd(idc.PrevHead(addr),1)
        elif idc.GetOpType(idc.PrevHead(idc.PrevHead(addr)),1) == 5:
           hash = idc.GetOpnd(idc.PrevHead(idc.PrevHead(addr)),1)
        elif idc.GetOpType(idc.PrevHead(idc.PrevHead(idc.PrevHead(addr))),1) == 5:
           hash = idc.GetOpnd(idc.PrevHead(idc.PrevHead(idc.PrevHead(addr))),1)

        hash = "0x" + hash.split('h')[0]
        libHashDict[hash.lower()] = idc.PrevHead(addr)
        
    for key, value in libHashDict.items():
        if key in exports.keys():
           resolved = exports[key]
           idc.MakeComm(value, str(resolved))

if __name__ == "__main__":
   xrefs_lib = idautils.CodeRefsTo(idc.LocByName("get_library_handle_sub_180001310"),0)
   resolve_CRC32Hash(xrefs_lib)
   xrefs_apis = idautils.CodeRefsTo(idc.LocByName("decrypt_API_sub_180001000"),0)
   resolve_CRC32Hash(xrefs_apis)
