import string
import idaapi
import idc
import idautils
import base64
import json
import string

MOD = 256
def KSA(key):
    key_length = len(key)
    S = range(MOD)
    j = 0
    for i in range(MOD):
        j = (j + S[i] + key[i % key_length]) % MOD
        S[i], S[j] = S[j], S[i]

    return S

def PRGA(S):
    i = 0
    j = 0
    while True:
        i = (i + 1) % MOD
        j = (j + S[i]) % MOD

        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % MOD]
        yield K

def get_keystream(key):
    S = KSA(key)
    return PRGA(S)


global strings_dict, procs_dict
strings_dict = {}

def decrypt_strings(main_refsList):
    """decryption sequence
      push offset aLq      ; "LQ=="
      call sub_422F70
      add  esp, 4
      mov  dword_4321D, eax
    """
    
    wrapper_decryptStrings = idc.LocByName(main_refsList[0])
    idc.MakeName(wrapper_decryptStrings, "wrapper_decryptStrings_"+main_refsList[0])
    
    decryptList = list(FuncItems(wrapper_decryptStrings))
    refsFrom_decryptList = [idc.GetOpnd(line,0) for line in decryptList if idc.GetMnem(line) == 'call']
    print len(refsFrom_decryptList)
    
    result = False
    sub_decryptaddr = ''
    
    if refsFrom_decryptList:
       result = all(element == refsFrom_decryptList[0] for element in refsFrom_decryptList)
       if result:
          sub_decryptaddr = set(refsFrom_decryptList)
    
    sub_decrypt = idc.LocByName(list(sub_decryptaddr)[0])
    idc.MakeName(sub_decrypt, "b64_RC4_decrypt")
    
    key = ''
    for addr in decryptList:
        optype = idc.GetOpType(addr,0)
        if optype == 2:
           # print idc.GetDisasm(addr)
           idc.MakeName(idc.GetOperandValue(addr,0), "key_offset")
           key = idc.GetString(idc.GetOperandValue(addr,1))
           break
    
    key = [ord(c) for c in key.encode('UTF-8')]
    
    sequence = ['push', 'call', 'add', 'mov']
    plaintext = ''
    for i in range(0, len(decryptList)-len(sequence)):
        if idc.GetMnem(decryptList[i]) in sequence:
           if idc.GetMnem(idc.NextHead(decryptList[i])) == 'call' and idc.GetOperandValue(idc.NextHead(decryptList[i]),0) == sub_decrypt:
              data = idc.GetString(idc.GetOperandValue(decryptList[i],0))
              decoded_data = bytearray(base64.b64decode(data))
              keystream = get_keystream(key)
              res = []
              for byte in decoded_data:
                  val = byte ^ next(keystream)
                  if val != 0:
                     res.append(chr(val))
                  else:
                     res.append('?')
              plaintext = ''.join(res)
              # print plaintext
              idc.MakeComm(decryptList[i], plaintext)
              var_addr = idc.GetOperandValue(decryptList[i + 3],0)
              strings_dict[var_addr] = plaintext
              plaintext = "".join([c for c in plaintext if (c in string.ascii_letters or c in string.digits)]).capitalize()
              plaintext = "str_" + plaintext
              idc.MakeName(var_addr, plaintext)


def resolve_apis(main_refsList):
    """GetProcaddress call pattern
    mov     ecx, str_Exitprocess
    push    ecx             ; lpProcName
    mov     edx, [ebp+pKernel32Base]
    push    edx             ; hModule
    call    getprocaddress
    mov     dword_4317B4, eax
    """
    pattern = ['mov', 'push', 'mov', 'push', 'call', 'mov']
    resolveList = list(FuncItems(idc.LocByName(main_refsList[1])))
    
    resolve_addrList = list(FuncItems(idc.LocByName(main_refsList[1])))
    idc.MakeName(idc.LocByName(main_refsList[1]), "resolveAPIs_"+main_refsList[1])
    resolve_refsList = [idc.GetOpnd(line,0) for line in resolve_addrList if idc.GetMnem(line) == 'call']
    
    idc.MakeName(idc.LocByName(resolve_refsList[0]), "load_kernel32dll_"+resolve_refsList[0])
    idc.MakeName(idc.LocByName(resolve_refsList[1]), "parse_kernel32dll_"+resolve_refsList[1])
    
    ea = idc.LocByName("parse_kernel32dll_"+resolve_refsList[1])
    xref = idautils.XrefsTo(ea, 0)
    loadlib_ref = idc.NextHead(idc.NextHead(next(xref).frm))
    idc.MakeName(idc.GetOperandValue(loadlib_ref, 0), "loadlibraryA")
    getprocaddr_ref = idc.NextHead(idc.NextHead(next(xref).frm))
    idc.MakeName(idc.GetOperandValue(getprocaddr_ref, 0), "getprocaddress")
    
    for i in range(0, len(resolveList)-len(pattern)):
      if idc.GetMnem(resolveList[i]) == 'call' and "getprocaddress" in idc.GetOpnd(resolveList[i], 0):
        addr = idc.GetOperandValue(resolveList[i-4],1)
        if addr in strings_dict:
            api = strings_dict[addr]
            resolvedaddr = idc.GetOperandValue(resolveList[i+1],0)
            idc.MakeName(resolvedaddr, "_"+api)

if __name__ == "__main__":
   main_addrList = list(FuncItems(idc.LocByName("_WinMain@16")))
   main_refsList = [idc.GetOpnd(line,0) for line in main_addrList if idc.GetMnem(line) == 'call'] 
   decrypt_strings(main_refsList)
   resolve_apis(main_refsList)
   
   idc.MakeName(idc.LocByName(main_refsList[2]), "CIS_check_"+main_refsList[2])
   idc.MakeName(idc.LocByName(main_refsList[3]), "windowsdefender_check_"+main_refsList[3])
   idc.MakeName(idc.LocByName(main_refsList[4]), "grabbing_module_"+main_refsList[4])