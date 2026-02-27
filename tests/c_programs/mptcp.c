#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>
#ifndef IPPROTO_MPTCP
#define IPPROTO_MPTCP 262
#endif
int main() {
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
    if (fd >= 0) close(fd);
    return EXIT_SUCCESS;
}
