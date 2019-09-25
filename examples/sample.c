#include <stdlib.h>
#include <sys/ptrace.h>
#include <stdio.h>

int main() {
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) 
    {
        printf("don't trace me !!\n");
        return 1;
    }
    printf("Everything is fine\n");
}
