#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    printf("Testing readonlybox client...\n");
    
    // Call a command that should go through the client
    char *args[] = { "vim", "--version", NULL };
    char *envp[] = { "PATH=/usr/bin:/bin", NULL };
    
    printf("Calling execve with LD_PRELOAD...\n");
    execve("/bin/vim", args, envp);
    
    perror("execve failed");
    return 1;
}
