#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static void die(const char *what) {
    perror(what);
    exit(1);
}

static int open_input(const char *path, char *name_buf, size_t name_len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        die(path);
    }
    memset(name_buf, 0, name_len);
    if (ioctl(fd, EVIOCGNAME((int)name_len), name_buf) < 0) {
        snprintf(name_buf, name_len, "unknown");
    }
    return fd;
}

int main(void) {
    char key_name[64];
    char mouse_name[64];
    int key_fd = open_input("/dev/input/event0", key_name, sizeof(key_name));
    int mouse_fd = open_input("/dev/input/mice", mouse_name, sizeof(mouse_name));

    struct input_id key_id;
    struct input_id mouse_id;
    int key_version = 0;
    int mouse_version = 0;
    if (ioctl(key_fd, EVIOCGID, &key_id) < 0) {
        die("EVIOCGID(event0)");
    }
    if (ioctl(mouse_fd, EVIOCGID, &mouse_id) < 0) {
        die("EVIOCGID(mice)");
    }
    if (ioctl(key_fd, EVIOCGVERSION, &key_version) < 0) {
        die("EVIOCGVERSION(event0)");
    }
    if (ioctl(mouse_fd, EVIOCGVERSION, &mouse_version) < 0) {
        die("EVIOCGVERSION(mice)");
    }

    struct pollfd pfds[2] = {
        {.fd = key_fd, .events = POLLIN},
        {.fd = mouse_fd, .events = POLLIN},
    };

    int saw_key_down = 0;
    int saw_key_up = 0;
    int saw_btn_down = 0;
    int saw_btn_up = 0;
    int rel_x = 0;
    int rel_y = 0;

    for (int round = 0; round < 20; round++) {
        int ready = poll(pfds, 2, 250);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            die("poll");
        }
        if (ready == 0) {
            continue;
        }
        for (int i = 0; i < 2; i++) {
            if ((pfds[i].revents & POLLIN) == 0) {
                continue;
            }
            struct input_event events[16];
            ssize_t n = read(pfds[i].fd, events, sizeof(events));
            if (n < 0) {
                if (errno == EAGAIN || errno == EINTR) {
                    continue;
                }
                die("read(input)");
            }
            size_t count = (size_t)n / sizeof(struct input_event);
            for (size_t j = 0; j < count; j++) {
                struct input_event *ev = &events[j];
                if (pfds[i].fd == key_fd) {
                    if (ev->type == EV_KEY && ev->code == KEY_A) {
                        if (ev->value == 1) {
                            saw_key_down = 1;
                        } else if (ev->value == 0) {
                            saw_key_up = 1;
                        }
                    }
                } else {
                    if (ev->type == EV_REL && ev->code == REL_X) {
                        rel_x += ev->value;
                    } else if (ev->type == EV_REL && ev->code == REL_Y) {
                        rel_y += ev->value;
                    } else if (ev->type == EV_KEY && ev->code == BTN_LEFT) {
                        if (ev->value == 1) {
                            saw_btn_down = 1;
                        } else if (ev->value == 0) {
                            saw_btn_up = 1;
                        }
                    }
                }
            }
        }
        if (saw_key_down && saw_key_up && rel_x != 0 && rel_y != 0 && saw_btn_down && saw_btn_up) {
            break;
        }
    }

    close(key_fd);
    close(mouse_fd);

    if (!(saw_key_down && saw_key_up && rel_x != 0 && rel_y != 0 && saw_btn_down && saw_btn_up)) {
        fprintf(stderr, "incomplete input capture key=(%d,%d) rel=(%d,%d) btn=(%d,%d)\n",
                saw_key_down, saw_key_up, rel_x, rel_y, saw_btn_down, saw_btn_up);
        return 2;
    }

    printf(
        "ev-lab keydev=%s keyver=%d key=A(down=%d,up=%d) mousedev=%s mousever=%d rel=(%d,%d) btn-left(down=%d,up=%d)\n",
        key_name,
        key_version,
        saw_key_down,
        saw_key_up,
        mouse_name,
        mouse_version,
        rel_x,
        rel_y,
        saw_btn_down,
        saw_btn_up
    );
    return 0;
}
