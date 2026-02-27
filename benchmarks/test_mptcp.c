#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <unistd.h>

#ifndef IPPROTO_MPTCP
#define IPPROTO_MPTCP 262
#endif

int main() {
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
    if (fd < 0) {
        perror("socket MPTCP");
        return 1;
    }
    printf("Socket MPTCP créé: fd=%d\n", fd);
    close(fd);
    return 0;
}
