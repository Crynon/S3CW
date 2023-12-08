from ROPcompile import dataaddressToValue
from ROPcompile import generalToBytes
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
    
def writeToData(state, position, value):
    numBytes = len(value)
    pos = int(position.lstrip("@ .dat+") or 0)
    state.datavalues = state.datavalues[:pos] + value + state.datavalues[pos + numBytes:]
    return

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

def setToLoc(state, name, value):
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
    if getFromLoc(state, r)[0] == '@':
        setToLoc(state, r, "@ .data + " + str(dataaddressToValue(getFromLoc(state, r)) + 1))
    else:
        setToLoc(state, r, pack("<I", int.from_bytes(getFromLoc(state, r), "little") + 1))

def dec(state, r):
    #increment value in r
    if getFromLoc(state, r)[0] == '@':
        setToLoc(state, r, "@ .data + " + str(dataaddressToValue(getFromLoc(state, r)) - 1))
    else:
        setToLoc(state, r, pack("<I", int.from_bytes(getFromLoc(state, r), "little") - 1))

def xchg(state, r1, r2):
    v1 = getFromLoc(state, r1)
    v2 = getFromLoc(state, r2)
    setToLoc(state, r1, v2)
    setToLoc(state, r2, v1)

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
    if command[0:3] == "dec":
        dec(state, command[4:])
    if command[0:3] == "xor":
        xor(state, command[4:], operand)
    if command[0:3] == "mov":
        mov(state, command[4:], operand)
    if command[0:3] == "pop":
        pop(state, command[4:])
    if command[0:1] == "@":
        endpop(state, command)
    if command[0:4] == "xchg":
        xchg(state, command[5:], operand)
    if command[0:3] == "nop":
        return state
    return state

def run(state, shellcode):
    for instruction in shellcode:
        transition(state, instruction)
