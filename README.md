# S3CW

Systems and Software Security Coursework

To run this software you must have [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) installed and available in the working directory.

The program takes 2 required arguments and 1 optional argument:
1. The location of the binary that you wish to generate an exploit for
2. The location of a file containing the shellcode you wish to execute
3. (OPTIONAL) The number of buffer characters at the start of the payload

Example:
```
$ python S3CW.py VulnerableBinaryFile exampleshell.txt 20
```
The shellcode file must contain a plaintext list of assembly instructions that should be executed on successful exploit of the vulnerable binary. Each instruction should be on its own line in the file and the file should contain no blank lines. For an example see exampleshell.txt

Each module can also be run individually to perform just their specific functions:

---

# Reverse Execution

Running this module alone will take a list of assembly instructions and rewrite it using only the gadgets that the system finds available for the given binary.

This module takes 2 required arguments:
1. The location of the binary that you wish to generate an exploit for
2. The location of a file containing the shellcode you wish to execute

Example:
```
$ python ReverseExecution.py VulnerableBinaryFile exampleshell.txt
```

The shellcode file must be in the same format as for S3CW.

The module will always output to a file called "RevExeOut.txt" in its directory.

---

# ROPcompile

Running this module alone will take a list of gadgets and output a payload file while contains those gadgets locations as a byte string assuming those gadgets can be found.

This module takes 2 required arguments and 1 optional argument:
1. The location of the binary that you wish to generate an exploit for
2. The location of a file containing the gadgets you wish to execute
3. (OPTIONAL) The offset from the locations of the gadgets in the binary to their location in memory

Example:
```
$ python ROPcompile.py VulnerableBinaryFile GadgetList 0xf7a80042
```

The module will not add any buffer values to the start of the payload when run alone.

The gadget file must be in the same format as for S3CW.

The module will always output to a file called "RopCompOut" in its directory.


