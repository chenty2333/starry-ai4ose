#define _GNU_SOURCE
#define _XOPEN_SOURCE 600

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

static int write_all(int fd, const char *buf, size_t len) {
    size_t offset = 0;
    while (offset < len) {
        ssize_t written = write(fd, buf + offset, len - offset);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        offset += (size_t)written;
    }
    return 0;
}

static int disable_echo(int fd) {
    struct termios tio;
    if (tcgetattr(fd, &tio) < 0) {
        return -1;
    }
    tio.c_lflag &= ~(ECHO | ECHONL);
    return tcsetattr(fd, TCSANOW, &tio);
}

static int connect_peer(const char *target) {
    const char *sep = strrchr(target, ':');
    char host[64];
    char *end = NULL;
    struct sockaddr_in addr = {0};
    long port = 0;
    int sock = -1;

    if (sep == NULL || sep == target || sep[1] == '\0') {
        errno = EINVAL;
        return -1;
    }
    if ((size_t)(sep - target) >= sizeof(host)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    memcpy(host, target, (size_t)(sep - target));
    host[sep - target] = '\0';
    port = strtol(sep + 1, &end, 10);
    if (end == NULL || *end != '\0' || port <= 0 || port > 65535) {
        errno = EINVAL;
        return -1;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        close(sock);
        errno = EINVAL;
        return -1;
    }
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    return sock;
}

static int relay_poll_loop(int master_fd, int input_fd, int output_fd, int input_open) {
    char buf[1024];

    for (;;) {
        struct pollfd fds[2];
        nfds_t nfds = 0;
        int had_input = input_open;

        if (had_input) {
            fds[nfds].fd = input_fd;
            fds[nfds].events = POLLIN | POLLHUP | POLLERR;
            nfds++;
        }

        fds[nfds].fd = master_fd;
        fds[nfds].events = POLLIN | POLLHUP | POLLERR;
        nfds++;

        if (poll(fds, nfds, -1) < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }

        if (had_input) {
            short revents = fds[0].revents;
            if (revents & POLLIN) {
                ssize_t n = read(input_fd, buf, sizeof(buf));
                if (n < 0) {
                    if (errno != EINTR) {
                        return -1;
                    }
                } else if (n == 0) {
                    input_open = 0;
                } else if (write_all(master_fd, buf, (size_t)n) < 0) {
                    return -1;
                }
            }
            if (revents & (POLLHUP | POLLERR)) {
                input_open = 0;
            }
        }

        short revents = fds[had_input ? 1 : 0].revents;
        if (revents & POLLIN) {
            ssize_t n = read(master_fd, buf, sizeof(buf));
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                if (errno == EIO) {
                    return 0;
                }
                return -1;
            }
            if (n == 0) {
                return 0;
            }
            if (write_all(output_fd, buf, (size_t)n) < 0) {
                return -1;
            }
        }
        if (revents & (POLLHUP | POLLERR)) {
            int flags = fcntl(master_fd, F_GETFL);
            if (flags >= 0) {
                (void)fcntl(master_fd, F_SETFL, flags | O_NONBLOCK);
            }
            for (;;) {
                ssize_t n = read(master_fd, buf, sizeof(buf));
                if (n > 0) {
                    if (write_all(output_fd, buf, (size_t)n) < 0) {
                        return -1;
                    }
                    continue;
                }
                if (n == 0) {
                    break;
                }
                if (errno == EINTR) {
                    continue;
                }
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EIO) {
                    break;
                }
                return -1;
            }
            return 0;
        }
    }
}

static int relay_select_loop(int master_fd, int input_fd, int output_fd, int input_open) {
    char ch = '\0';

    for (;;) {
        fd_set readfds;
        int maxfd = master_fd;

        FD_ZERO(&readfds);
        FD_SET(master_fd, &readfds);
        if (input_open) {
            FD_SET(input_fd, &readfds);
            if (input_fd > maxfd) {
                maxfd = input_fd;
            }
        }

        if (select(maxfd + 1, &readfds, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }

        if (input_open && FD_ISSET(input_fd, &readfds)) {
            ssize_t n = read(input_fd, &ch, 1);
            if (n < 0) {
                if (errno != EINTR) {
                    return -1;
                }
            } else if (n == 0) {
                input_open = 0;
            } else if (write_all(master_fd, &ch, 1) < 0) {
                return -1;
            }
        }

        if (!FD_ISSET(master_fd, &readfds)) {
            continue;
        }

        ssize_t n = read(master_fd, &ch, 1);
        if (n > 0) {
            if (write_all(output_fd, &ch, 1) < 0) {
                return -1;
            }
            continue;
        }
        if (n == 0) {
            return 0;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EIO) {
            return 0;
        }
        return -1;
    }
}

static int relay_loop(int master_fd, int input_fd, int output_fd, int input_open, int use_select) {
    if (use_select) {
        return relay_select_loop(master_fd, input_fd, output_fd, input_open);
    }
    return relay_poll_loop(master_fd, input_fd, output_fd, input_open);
}

static char *load_script(const char *path, size_t *len_out) {
    FILE *fp = fopen(path, "rb");
    char *buf = NULL;
    long size = 0;

    if (fp == NULL) {
        return NULL;
    }
    if (fseek(fp, 0, SEEK_END) < 0) {
        fclose(fp);
        return NULL;
    }
    size = ftell(fp);
    if (size < 0) {
        fclose(fp);
        return NULL;
    }
    if (fseek(fp, 0, SEEK_SET) < 0) {
        fclose(fp);
        return NULL;
    }

    buf = malloc((size_t)size);
    if (buf == NULL) {
        fclose(fp);
        return NULL;
    }
    if (size > 0 && fread(buf, 1, (size_t)size, fp) != (size_t)size) {
        free(buf);
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    *len_out = (size_t)size;
    return buf;
}

static int write_script(int master_fd, const char *buf, size_t len) {
    usleep(300000);
    for (size_t i = 0; i < len; i++) {
        char ch = buf[i] == '\n' ? '\r' : buf[i];
        if (write_all(master_fd, &ch, 1) < 0) {
            return -1;
        }
        usleep(5000);
    }
    return 0;
}

int main(int argc, char **argv) {
    static char *default_argv[] = {"/bin/sh", "-i", NULL};
    char *slave_name = NULL;
    const char *peer_target = NULL;
    const char *script_path = NULL;
    char *script_buf = NULL;
    size_t script_len = 0;
    int no_input = 0;
    int use_select = 0;
    int master_fd = -1;
    int peer_fd = -1;
    pid_t child = -1;
    int status = 1;
    int argi = 1;

    signal(SIGPIPE, SIG_IGN);

    while (argi < argc) {
        if (strcmp(argv[argi], "-s") == 0) {
            use_select = 1;
            argi++;
            continue;
        }
        if (strcmp(argv[argi], "-t") == 0 && argi + 1 < argc) {
            peer_target = argv[argi + 1];
            argi += 2;
            continue;
        }
        if (strcmp(argv[argi], "-f") == 0 && argi + 1 < argc) {
            script_path = argv[argi + 1];
            argi += 2;
            continue;
        }
        if (strcmp(argv[argi], "-n") == 0) {
            no_input = 1;
            argi++;
            continue;
        }
        break;
    }

    char **child_argv = argi < argc ? &argv[argi] : default_argv;

    master_fd = posix_openpt(O_RDWR | O_NOCTTY);
    if (master_fd < 0) {
        perror("posix_openpt");
        return 1;
    }
    if (grantpt(master_fd) < 0) {
        perror("grantpt");
        close(master_fd);
        return 1;
    }
    if (unlockpt(master_fd) < 0) {
        perror("unlockpt");
        close(master_fd);
        return 1;
    }

    slave_name = ptsname(master_fd);
    if (slave_name == NULL) {
        perror("ptsname");
        close(master_fd);
        return 1;
    }

    child = fork();
    if (child < 0) {
        perror("fork");
        close(master_fd);
        return 1;
    }

    if (child == 0) {
        int slave_fd = -1;

        if (setsid() < 0) {
            perror("setsid");
            _exit(1);
        }

        slave_fd = open(slave_name, O_RDWR);
        if (slave_fd < 0) {
            perror("open slave");
            _exit(1);
        }
        if (ioctl(slave_fd, TIOCSCTTY, 0) < 0) {
            perror("ioctl(TIOCSCTTY)");
            _exit(1);
        }
        if (disable_echo(slave_fd) < 0) {
            perror("disable_echo");
            _exit(1);
        }

        if (dup2(slave_fd, STDIN_FILENO) < 0 ||
            dup2(slave_fd, STDOUT_FILENO) < 0 ||
            dup2(slave_fd, STDERR_FILENO) < 0) {
            perror("dup2");
            _exit(1);
        }

        if (slave_fd > STDERR_FILENO) {
            close(slave_fd);
        }
        close(master_fd);

        setenv("PS1", "", 1);
        execvp(child_argv[0], child_argv);
        perror("execvp");
        _exit(127);
    }

    if (script_path != NULL) {
        script_buf = load_script(script_path, &script_len);
        if (script_buf == NULL) {
            perror("load_script");
            close(master_fd);
            return 1;
        }
        if (write_script(master_fd, script_buf, script_len) < 0) {
            perror("write script");
            free(script_buf);
            close(master_fd);
            return 1;
        }
        free(script_buf);
        status = relay_loop(master_fd, -1, STDOUT_FILENO, 0, use_select);
    } else if (peer_target != NULL) {
        peer_fd = connect_peer(peer_target);
        if (peer_fd < 0) {
            perror("connect_peer");
            close(master_fd);
            return 1;
        }
        usleep(300000);
        status = relay_loop(master_fd, peer_fd, peer_fd, 1, use_select);
        close(peer_fd);
    } else if (no_input) {
        status = relay_loop(master_fd, -1, STDOUT_FILENO, 0, use_select);
    } else {
        status = relay_loop(master_fd, STDIN_FILENO, STDOUT_FILENO, 1, use_select);
    }
    close(master_fd);

    for (;;) {
        int wait_status = 0;
        pid_t waited = waitpid(child, &wait_status, 0);
        if (waited < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("waitpid");
            return 1;
        }
        if (WIFEXITED(wait_status)) {
            return WEXITSTATUS(wait_status);
        }
        if (WIFSIGNALED(wait_status)) {
            return 128 + WTERMSIG(wait_status);
        }
        return status == 0 ? 0 : 1;
    }
}
