#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

int main() {
    int pipefd[2];
    if (pipe(pipefd) == -1) exit(1);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8000);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    // On tente la connexion (silencieusement)
    connect(sock, (struct sockaddr *)&addr, sizeof(addr));

    write(pipefd[1], "test_splice", 11);

    // Splice zero-copy
    splice(pipefd[0], NULL, sock, NULL, 11, SPLICE_F_MOVE);

    close(pipefd[0]);
    close(pipefd[1]);
    close(sock);
    return 0;
}