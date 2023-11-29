import copy
from struct import pack

ACC_NAME = "eax"
COUNT_NAME = "ecx"
DATA_NAME = "edx"
BASE_NAME = "ebx"
SPOINT_NAME = "esp"
SBASE_NAME = "ebp"
SOURCE_NAME = "esi"
DEST_NAME = "rdi"

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
        print(ACC_NAME + " : " + str(int.from_bytes(self.acc, "little")))
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

def writeToData(state, position, value):
    numBytes = len(value)
    pos = int(position.lstrip(" .dat+") or 0)
    state.datavalues = state.datavalues[:pos] + value + state.datavalues[pos + numBytes:]
    return

def setToLoc(state, name, value):
    print("set " + name)
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
    if name[0:5] == ".data":
        writeToData(state, name, value)
    if name[0:11] == "dword ptr [":
        setToLoc(state, getFromLoc(state, name[11:14]), value)

def inc(state, r):
    #increment value in r
    setToLoc(state, r, pack("<I", int.from_bytes(getFromLoc(state, r), "little") + 1))

def xor(state, d, s):
    #xor d with s and store in d
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
    if type(instruction) is bytes:
        endpop(state, instruction)
        return state
    
    parts = [x.strip() for x in instruction.split(",")]
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
        endpop(state, command[2:])
    return state

def run(state, shellcode):
    for instruction in shellcode:
        transition(state, instruction)

def createGoal(shellcode):
    goal = SysState()
    run(goal, shellcode)
    return goal

def findRegistersForDataWrite(Gadgets):
    #find all registers which can be used as pointers to data in order to write
    accumulator = False
    for g in Gadgets:
        if g == "mov dword ptr [eax]":
            accumulator = True

#shellcode should be a list of assembly instructions as strings
#gadgets should be a list of gadgets that will be available as strings
def create(shellcode, gadgets):
    #Generate Goal State
    Goal = createGoal(shellcode)
    Goal.printSystem()
    #Initialise Simulation
    GadgetSequence = []
    InitialState = SysState()
    System = copy.deepcopy(Goal)
    #Reverse Execution from goal
        #Load to .data
    while System.datavalues != Goal.datavalues:
        System.datavalues = Goal.datavalues # TODO
        #Load register values
    #Return Sequence of Gadgets

if __name__ == "__main__":
    TestSystem = SysState()
    transition(TestSystem, "pop edx")
    transition(TestSystem, "@ .data")
    transition(TestSystem, "pop eax")
    transition(TestSystem, b'/bin')
    transition(TestSystem, "mov dword ptr [edx], eax")
    transition(TestSystem, "pop edx")
    transition(TestSystem, "@ .data + 4")
    transition(TestSystem, "pop eax")
    transition(TestSystem, b'//sh')
    transition(TestSystem, "mov dword ptr [edx], eax")
    transition(TestSystem, "pop edx")
    transition(TestSystem, "@ .data + 8")
    transition(TestSystem, "xor eax, eax")
    transition(TestSystem, "mov dword ptr [edx], eax")
    transition(TestSystem, "pop ebx")
    transition(TestSystem, "@ .data")
    run(TestSystem, ["pop ecx", "pop ebx"])
    transition(TestSystem, "@ .data + 8")
    transition(TestSystem, "@ .data")
    transition(TestSystem, "pop edx")
    transition(TestSystem, "@ .data + 8")
    transition(TestSystem, "xor eax, eax")
    run(TestSystem, ["inc eax"]*11)
    TestSystem.printSystem()

    print("CREATE TEST")
    create(["pop edx", "@ .data", "pop eax", b'/bin', "mov dword ptr [edx], eax", "pop edx", "@ .data + 4", "pop eax", b'//sh', "mov dword ptr [edx], eax", "pop edx", "@ .data + 8", "xor eax, eax", "mov dword ptr [edx], eax", "pop ebx", "@ .data", "pop ecx", "pop ebx", "@ .data + 8", "@ .data", "pop edx", "@ .data + 8", "xor eax, eax"] + ["inc eax"]*11, None)