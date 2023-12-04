# S3CW

Systems and Software Security Coursework

To run this software you must have [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) installed and available in the working directory.

The program takes exactly 2 arguments:
1. The location of the binary that you wish to generate an exploit for
2. The location of a file containing the shellcode you wish to execute

The shellcode file must contain a plaintext list of assembly instructions that should be executed on successful exploit of the vulnerable binary. Each instruction should be on its own line in the file and the file should contain no blank lines.