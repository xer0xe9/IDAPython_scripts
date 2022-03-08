import json
import idc
import idautils

exports = {}
f = open('exports.json', 'r')
exports = json.load(f)


def resolve_CRC32Hash(xrefs_to):
    libHashDict = {}
    crc32_hash = ""
    hash_addr = 0
    for addr in xrefs_to:
        if idc.GetOpType(idc.PrevHead(addr),1) == 5:
           hash_addr = idc.PrevHead(addr)
           crc32_hash = idc.GetOpnd(idc.PrevHead(addr),1)
        elif idc.GetOpType(idc.PrevHead(idc.PrevHead(addr)),1) == 5:
           hash_addr = idc.PrevHead(idc.PrevHead(addr))
           crc32_hash = idc.GetOpnd(idc.PrevHead(idc.PrevHead(addr)),1)
        elif idc.GetOpType(idc.PrevHead(idc.PrevHead(idc.PrevHead(addr))),1) == 5:
           hash_addr = idc.PrevHead(idc.PrevHead(idc.PrevHead(addr)))
           crc32_hash = idc.GetOpnd(idc.PrevHead(idc.PrevHead(idc.PrevHead(addr))),1)

        # print hex(hash_addr)
        # sanitize hash value
        if crc32_hash:
           crc32_hash = crc32_hash[:-1]
           if crc32_hash[0] == "0":
              crc32_hash = crc32_hash[1:]
           crc32_hash = "0x" + crc32_hash

        libHashDict[crc32_hash.lower()] = hash_addr

    for key, value in libHashDict.items():
        if key in exports.keys():
           resolved = exports[key]
           idc.MakeComm(value, str(resolved))
        else:
          print "key ", key, " not found."

if __name__ == "__main__":
   xrefs_lib = idautils.CodeRefsTo(idc.LocByName("get_library_handle_sub_180001310"),0)
   resolve_CRC32Hash(xrefs_lib)
   xrefs_apis = idautils.CodeRefsTo(idc.LocByName("decrypt_API_sub_180001000"),0)
   resolve_CRC32Hash(xrefs_apis)