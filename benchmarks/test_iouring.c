#include <liburing.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

int main() {
    struct io_uring ring;
    io_uring_queue_init(8, &ring, 0);

    int fd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(80),
    };
    inet_pton(AF_INET, "93.184.216.34", &addr.sin_addr); // example.com

    // Soumettre un connect via io_uring
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    io_uring_prep_connect(sqe, fd, (struct sockaddr *)&addr, sizeof(addr));
    sqe->user_data = fd; // fd comme user_data -> corrélation session_id

    io_uring_submit(&ring);

    struct io_uring_cqe *cqe;
    io_uring_wait_cqe(&ring, &cqe);
    printf("io_uring connect result: %d\n", cqe->res);
    io_uring_cqe_seen(&ring, cqe);

    io_uring_queue_exit(&ring);
    close(fd);
    return 0;
}
