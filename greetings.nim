#[
    Author: StudyCat
    Blog: https://www.cnblogs.com/studycat
    Github: https://github.com/StudyCat404/uuid_exec_shellcode

    References:
        - https://github.com/ChoiSG/UuidShellcodeExec/blob/main/shellcodeToUUID.py
]#
import winim
import os
import base64
import random

proc gkkaekgaEE(s: string, key: int): string {.noinline.} =
  # We need {.noinline.} here because otherwise C compiler
  # aggresively inlines this procedure for EACH string which results
  # in more assembly instructions
  var k = key
  result = string(s)
  for i in 0 ..< result.len:
    for f in [0, 8, 16, 24]:
      result[i] = chr(uint8(result[i]) xor uint8((k shr f) and 0xFF))
    k = k +% 1    
    
proc convertToUUID(shellcode: var seq[byte]) =  
    var 
        fileName = "uuid.txt"
        outFile: File
        password: int
    outFile = open(fileName, fmAppend)    
    randomize()
    password = rand(1024..65535)
    echo "XOR Password: ", password
    
    if len(shellcode) div 16 != 0 :
        for i in 1..(16 - (len(shellcode) mod 16)):
            shellcode.add(0x00)
    else:
        echo "test"
    for i in 0..(len(shellcode) div 16 - 1):
        var 
            s = i*16
            e = s+15
            buf = shellcode[s..e]
            uid: UUID
            uidStr: RPC_CSTR
            line = ""
            
        copyMem(addr uid, addr buf[0], len(buf))
        UuidToStringA(addr uid, addr uidStr)
        #line = "\"" & $uidStr & "\","
        line = "\"" & encode(gkkaekgaEE($uidStr, password)) & "\"," 
        outFile.writeLine(line)
    outFile.close()
 
proc convertToUUID(fileName: string) =
    if fileExists(fileName):
        echo "Convert ", fileName, " to string UUID"
        echo "Output file: uuid.txt"
        var f: File
        f = open(fileName,fmRead)   
        var fileSize = f.getFileSize()
        var shellcode = newSeq[byte](fileSize)
        discard readBytes(f,shellcode,0,fileSize)
        convertToUUID(shellcode)
        f.close()
    else:
        echo "The system cannot find the file specified."
    
proc help() =
    let pathSplit = splitPath(paramStr(0))
    echo "Usage:"
    echo "\t", pathSplit.tail, " filename"

when defined(windows):
    when isMainModule:
        if paramCount() > 0:
            var p1 = paramStr(1)
            if p1 in ["/?","-h","--help"]:
                help()
            else:
                convertToUUID(p1)
        else:
            help()