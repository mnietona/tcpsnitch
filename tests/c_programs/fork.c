#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>

int main() {
    pid_t pid = fork();
    
    if (pid < 0) exit(1);

    if (pid == 0) {
        // Enfant
        usleep(100000); 
        int s_child = socket(AF_INET, SOCK_STREAM, 0);
        if (s_child >= 0) close(s_child);
        usleep(500000); 
        _exit(0); 
    } else {
        // Parent
        int s_parent = socket(AF_INET, SOCK_STREAM, 0);
        if (s_parent >= 0) close(s_parent);
        wait(NULL); 
        usleep(500000); 
        exit(0);
    }
}