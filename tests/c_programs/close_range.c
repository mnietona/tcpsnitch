#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
int main() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    close_range(sock, sock, 0);
    return EXIT_SUCCESS;
}