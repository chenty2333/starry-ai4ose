#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(const char *prog) {
    fprintf(stderr, "usage: %s <write|read>\n", prog);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        usage(argv[0]);
        return 2;
    }

    sleep(1);

    if (strcmp(argv[1], "write") == 0) {
        const char payload[] = "sigttou-lab\n";
        for (;;) {
            ssize_t written = write(STDOUT_FILENO, payload, sizeof(payload) - 1);
            if (written == (ssize_t)(sizeof(payload) - 1)) {
                return 0;
            }
            if (written < 0 && errno == EINTR) {
                continue;
            }
            if (written < 0) {
                perror("write(stdout)");
            } else {
                fprintf(stderr, "short write: %zd\n", written);
            }
            return 1;
        }
    }

    if (strcmp(argv[1], "read") == 0) {
        char buf[128];
        for (;;) {
            ssize_t n = read(STDIN_FILENO, buf, sizeof(buf) - 1);
            if (n > 0) {
                while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) {
                    n--;
                }
                buf[n] = '\0';
                dprintf(STDOUT_FILENO, "sigttin:%s\n", buf);
                return 0;
            }
            if (n < 0 && errno == EINTR) {
                continue;
            }
            if (n == 0) {
                fprintf(stderr, "read(stdin): EOF\n");
            } else {
                perror("read(stdin)");
            }
            return 1;
        }
    }

    usage(argv[0]);
    return 2;
}
