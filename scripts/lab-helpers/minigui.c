#include <errno.h>
#include <fcntl.h>
#include <linux/fb.h>
#include <linux/input.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

static void die(const char *what) {
    perror(what);
    exit(1);
}

static uint32_t pack_rgb(uint8_t r, uint8_t g, uint8_t b) {
    return 0xff000000u | ((uint32_t)r << 16) | ((uint32_t)g << 8) | (uint32_t)b;
}

static void put_pixel(uint8_t *base, const struct fb_fix_screeninfo *fix, int x, int y, uint32_t color) {
    uint32_t *pixel = (uint32_t *)(base + (size_t)y * fix->line_length + (size_t)x * 4);
    *pixel = color;
}

static void fill_rect(
    uint8_t *base,
    const struct fb_fix_screeninfo *fix,
    int x,
    int y,
    int w,
    int h,
    uint32_t color
) {
    for (int yy = 0; yy < h; yy++) {
        for (int xx = 0; xx < w; xx++) {
            put_pixel(base, fix, x + xx, y + yy, color);
        }
    }
}

static void draw_box(
    uint8_t *base,
    const struct fb_fix_screeninfo *fix,
    int x,
    int y,
    int w,
    int h,
    uint32_t border,
    uint32_t fill
) {
    fill_rect(base, fix, x, y, w, h, fill);
    fill_rect(base, fix, x, y, w, 2, border);
    fill_rect(base, fix, x, y + h - 2, w, 2, border);
    fill_rect(base, fix, x, y, 2, h, border);
    fill_rect(base, fix, x + w - 2, y, 2, h, border);
}

static void draw_cursor(
    uint8_t *base,
    const struct fb_fix_screeninfo *fix,
    int cx,
    int cy,
    int width,
    int height,
    uint32_t color
) {
    for (int dx = -8; dx <= 8; dx++) {
        int x = cx + dx;
        if (x >= 0 && x < width && cy >= 0 && cy < height) {
            put_pixel(base, fix, x, cy, color);
        }
    }
    for (int dy = -8; dy <= 8; dy++) {
        int y = cy + dy;
        if (cx >= 0 && cx < width && y >= 0 && y < height) {
            put_pixel(base, fix, cx, y, color);
        }
    }
}

static uint32_t rolling_checksum(const uint8_t *base, size_t size) {
    uint32_t acc = 2166136261u;
    for (size_t i = 0; i < size; i += 97) {
        acc ^= base[i];
        acc *= 16777619u;
    }
    return acc;
}

struct scene_state {
    int box_x;
    int box_y;
    int box_w;
    int box_h;
    int cursor_x;
    int cursor_y;
    int box_variant;
};

static void render_scene(
    uint8_t *fb,
    size_t map_len,
    const struct fb_fix_screeninfo *fix,
    int width,
    int height,
    const struct scene_state *state
) {
    (void)map_len;
    const uint32_t background = pack_rgb(18, 25, 35);
    const uint32_t band = pack_rgb(33, 150, 243);
    const uint32_t grid = pack_rgb(28, 37, 48);
    const uint32_t box_fill = state->box_variant ? pack_rgb(255, 204, 64) : pack_rgb(92, 184, 92);
    const uint32_t box_border = pack_rgb(250, 250, 250);
    const uint32_t cursor = pack_rgb(244, 67, 54);

    memset(fb, 0, map_len);
    fill_rect(fb, fix, 0, 0, width, height, background);
    fill_rect(fb, fix, 0, 0, width, height / 8, band);

    for (int x = 0; x < width; x += 80) {
        fill_rect(fb, fix, x, 0, 1, height, grid);
    }
    for (int y = height / 8; y < height; y += 80) {
        fill_rect(fb, fix, 0, y, width, 1, grid);
    }

    draw_box(
        fb,
        fix,
        state->box_x,
        state->box_y,
        state->box_w,
        state->box_h,
        box_border,
        box_fill
    );
    draw_cursor(fb, fix, state->cursor_x, state->cursor_y, width, height, cursor);
}

static int open_input(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        die(path);
    }
    return fd;
}

static int clampi(int value, int low, int high) {
    if (value < low) {
        return low;
    }
    if (value > high) {
        return high;
    }
    return value;
}

int main(void) {
    int fb_fd = open("/dev/fb0", O_RDWR);
    if (fb_fd < 0) {
        die("open(/dev/fb0)");
    }

    struct fb_var_screeninfo var;
    struct fb_fix_screeninfo fix;
    if (ioctl(fb_fd, FBIOGET_VSCREENINFO, &var) < 0) {
        die("FBIOGET_VSCREENINFO");
    }
    if (ioctl(fb_fd, FBIOGET_FSCREENINFO, &fix) < 0) {
        die("FBIOGET_FSCREENINFO");
    }
    if (var.bits_per_pixel != 32) {
        fprintf(stderr, "unsupported bpp: %u\n", var.bits_per_pixel);
        return 2;
    }

    size_t map_len = fix.smem_len;
    uint8_t *fb = mmap(NULL, map_len, PROT_READ | PROT_WRITE, MAP_SHARED, fb_fd, 0);
    if (fb == MAP_FAILED) {
        die("mmap(/dev/fb0)");
    }

    int key_fd = open_input("/dev/input/event0");
    int mouse_fd = open_input("/dev/input/mice");

    int width = (int)var.xres;
    int height = (int)var.yres;
    struct scene_state state = {
        .box_x = width / 5,
        .box_y = height / 3,
        .box_w = width / 7,
        .box_h = height / 6,
        .cursor_x = width / 2,
        .cursor_y = height / 2,
        .box_variant = 0,
    };
    render_scene(fb, map_len, &fix, width, height, &state);

    struct pollfd pfds[2] = {
        {.fd = key_fd, .events = POLLIN},
        {.fd = mouse_fd, .events = POLLIN},
    };

    int saw_d = 0;
    int saw_s = 0;
    int saw_click_down = 0;
    int saw_click_up = 0;
    int saw_mouse_move = 0;

    for (int round = 0; round < 32; round++) {
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
                if (errno == EINTR || errno == EAGAIN) {
                    continue;
                }
                die("read(input)");
            }
            size_t count = (size_t)n / sizeof(struct input_event);
            for (size_t j = 0; j < count; j++) {
                const struct input_event *ev = &events[j];
                if (pfds[i].fd == key_fd) {
                    if (ev->type == EV_KEY && ev->value == 1) {
                        if (ev->code == KEY_D) {
                            state.box_x = clampi(state.box_x + 40, 0, width - state.box_w);
                            saw_d = 1;
                        } else if (ev->code == KEY_S) {
                            state.box_y = clampi(state.box_y + 28, height / 8, height - state.box_h);
                            saw_s = 1;
                        }
                    }
                } else {
                    if (ev->type == EV_REL && ev->code == REL_X) {
                        state.cursor_x = clampi(state.cursor_x + ev->value, 0, width - 1);
                        if (ev->value != 0) {
                            saw_mouse_move = 1;
                        }
                    } else if (ev->type == EV_REL && ev->code == REL_Y) {
                        state.cursor_y = clampi(state.cursor_y + ev->value, 0, height - 1);
                        if (ev->value != 0) {
                            saw_mouse_move = 1;
                        }
                    } else if (ev->type == EV_KEY && ev->code == BTN_LEFT) {
                        if (ev->value == 1) {
                            saw_click_down = 1;
                            state.box_variant = 1;
                        } else if (ev->value == 0) {
                            saw_click_up = 1;
                        }
                    }
                }
            }
            render_scene(fb, map_len, &fix, width, height, &state);
        }
        if (saw_d && saw_s && saw_mouse_move && saw_click_down && saw_click_up) {
            break;
        }
    }

    struct timespec delay = {.tv_sec = 0, .tv_nsec = 200 * 1000 * 1000};
    nanosleep(&delay, NULL);

    uint32_t checksum = rolling_checksum(fb, map_len);
    close(key_fd);
    close(mouse_fd);
    if (munmap(fb, map_len) < 0) {
        die("munmap(/dev/fb0)");
    }
    close(fb_fd);

    if (!(saw_d && saw_s && saw_mouse_move && saw_click_down && saw_click_up)) {
        fprintf(
            stderr,
            "incomplete gui interaction d=%d s=%d move=%d click=(%d,%d)\n",
            saw_d,
            saw_s,
            saw_mouse_move,
            saw_click_down,
            saw_click_up
        );
        return 2;
    }

    printf(
        "gui-lab box=(%d,%d) cursor=(%d,%d) color=%s checksum=0x%08x\n",
        state.box_x,
        state.box_y,
        state.cursor_x,
        state.cursor_y,
        state.box_variant ? "amber" : "green",
        checksum
    );
    return 0;
}
