import idc, idautils

#Link: https://bazaar.abuse.ch/sample/54b0ab0858e86f2e955c81bf2ede5b9b821f8426794bd92e7aa8180afb83457e/
#md5:641645f7373be3c2e7575bcc67256a95


def ROL(data, shift, size=32):
    shift %= size
    remains = data >> (size - shift)
    body = (data << shift) - (remains << size )
    return (body + remains)
 
ea = idc.LocByName("sub_14000B79C")
for xref in idautils.XrefsTo(ea, 1):
    enc_str_addr = 0
    if idc.GetMnem(xref.frm) == "call":
       xref_frm = xref.frm
       if idc.GetMnem(idc.PrevHead(xref_frm)) == "lea" and idc.GetOpType(idc.PrevHead(xref_frm), 1) == 2:
          enc_str_addr = idc.GetOperandValue(idc.PrevHead(xref_frm), 1)
       else:
          xref_frm = idc.PrevHead(idc.PrevHead(xref_frm))
          if idc.GetMnem(xref_frm) == "lea" and idc.GetOpType(xref_frm, 1) == 2:
             enc_str_addr = idc.GetOperandValue(xref_frm, 1)
          else:
             xref_frm = idc.PrevHead(xref_frm)
             if idc.GetMnem(xref_frm) == "lea" and idc.GetOpType(xref_frm, 1) == 2:
                enc_str_addr = idc.GetOperandValue(xref_frm, 1)
 
    if enc_str_addr:
       dword_val1 = idc.Dword(enc_str_addr)
       word_val2 = idc.Word(enc_str_addr+4)
       str_len = dword_val1 ^ word_val2
       str_len &= 0xff
       enc_str_start_offset = enc_str_addr+6
       enc_str_end = str_len - 1
       seed = dword_val1
       plaintext = ""
       for byte in idc.GetManyBytes(enc_str_start_offset, enc_str_end):
           c = seed
           c = ROL(c,3)
           a = c - 0xCED2
           a = ROL(a,1)
           a = a + 0x5C85
           a = ROL(a,1)
           a = a ^ 0xD993
           seed = a
           a &= 0xff
           key = a
           dec = ord(byte) ^ int(key)
           if dec != 0:
              plaintext += chr(dec)
       print plaintext