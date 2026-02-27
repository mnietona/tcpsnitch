#include <liburing.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>
int main() {
    struct io_uring ring;
    if (io_uring_queue_init(8, &ring, 0) < 0) return EXIT_FAILURE;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    io_uring_queue_exit(&ring);
    close(fd);
    return EXIT_SUCCESS;
}