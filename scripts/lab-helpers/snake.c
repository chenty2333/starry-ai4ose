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

#define MAX_SNAKE_LEN 256

struct point {
    int x;
    int y;
};

struct game_state {
    int grid_w;
    int grid_h;
    int cell;
    int origin_x;
    int origin_y;
    int dir_x;
    int dir_y;
    int snake_len;
    struct point snake[MAX_SNAKE_LEN];
    struct point food;
    unsigned food_seed;
    int score;
    int alive;
    int quit;
    int scripted;
    int scripted_food_index;
    struct point scripted_foods[3];
};

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

static uint32_t rolling_checksum(const uint8_t *base, size_t size) {
    uint32_t acc = 2166136261u;
    for (size_t i = 0; i < size; i += 97) {
        acc ^= base[i];
        acc *= 16777619u;
    }
    return acc;
}

static int open_keyboard(void) {
    int fd = open("/dev/input/event0", O_RDONLY);
    if (fd < 0) {
        die("open(/dev/input/event0)");
    }
    return fd;
}

static int point_eq(struct point a, struct point b) {
    return a.x == b.x && a.y == b.y;
}

static int snake_contains(const struct game_state *state, struct point p) {
    for (int i = 0; i < state->snake_len; i++) {
        if (point_eq(state->snake[i], p)) {
            return 1;
        }
    }
    return 0;
}

static struct point next_food_candidate(struct game_state *state) {
    state->food_seed = state->food_seed * 1103515245u + 12345u;
    unsigned span = (unsigned)(state->grid_w * state->grid_h);
    unsigned idx = (state->food_seed >> 8) % span;
    struct point p = {
        .x = (int)(idx % (unsigned)state->grid_w),
        .y = (int)(idx / (unsigned)state->grid_w),
    };
    return p;
}

static void place_food(struct game_state *state) {
    if (state->scripted && state->scripted_food_index < 3) {
        state->food = state->scripted_foods[state->scripted_food_index++];
        return;
    }
    for (int tries = 0; tries < state->grid_w * state->grid_h * 2; tries++) {
        struct point candidate = next_food_candidate(state);
        if (!snake_contains(state, candidate)) {
            state->food = candidate;
            return;
        }
    }
    state->food = (struct point){.x = 1, .y = 1};
}

static void init_game(struct game_state *state, int width, int height, int scripted) {
    memset(state, 0, sizeof(*state));
    state->cell = width / 26;
    if (state->cell > (height - 80) / 18) {
        state->cell = (height - 80) / 18;
    }
    if (state->cell < 20) {
        state->cell = 20;
    }
    state->grid_w = 20;
    state->grid_h = 12;
    state->origin_x = (width - state->grid_w * state->cell) / 2;
    state->origin_y = 70;
    state->dir_x = 1;
    state->dir_y = 0;
    state->snake_len = 4;
    state->alive = 1;
    state->scripted = scripted;
    state->food_seed = 0x5eed1234u;

    int start_y = state->grid_h / 2;
    int start_x = state->grid_w / 2 - 3;
    for (int i = 0; i < state->snake_len; i++) {
        state->snake[i] = (struct point){.x = start_x + i, .y = start_y};
    }

    struct point head = state->snake[state->snake_len - 1];
    state->scripted_foods[0] = (struct point){.x = head.x + 2, .y = head.y};
    state->scripted_foods[1] = (struct point){.x = head.x + 2, .y = head.y + 2};
    state->scripted_foods[2] = (struct point){.x = head.x + 1, .y = head.y + 2};
    place_food(state);
}

static void render_scene(
    uint8_t *fb,
    size_t map_len,
    const struct fb_fix_screeninfo *fix,
    const struct game_state *state
) {
    (void)map_len;
    const uint32_t background = pack_rgb(12, 18, 25);
    const uint32_t header = pack_rgb(32, 41, 56);
    const uint32_t board = pack_rgb(26, 34, 44);
    const uint32_t grid = pack_rgb(18, 24, 31);
    const uint32_t snake_body = pack_rgb(76, 175, 80);
    const uint32_t snake_head = pack_rgb(174, 234, 0);
    const uint32_t food = pack_rgb(239, 83, 80);
    const uint32_t border = state->alive ? pack_rgb(250, 250, 250) : pack_rgb(244, 67, 54);

    memset(fb, 0, map_len);
    fill_rect(fb, fix, 0, 0, fix->line_length / 4, state->origin_y + state->grid_h * state->cell + 32, background);
    fill_rect(fb, fix, 0, 0, fix->line_length / 4, 52, header);

    int board_x = state->origin_x - 4;
    int board_y = state->origin_y - 4;
    int board_w = state->grid_w * state->cell + 8;
    int board_h = state->grid_h * state->cell + 8;
    fill_rect(fb, fix, board_x, board_y, board_w, board_h, border);
    fill_rect(fb, fix, state->origin_x, state->origin_y, state->grid_w * state->cell, state->grid_h * state->cell, board);

    for (int x = 1; x < state->grid_w; x++) {
        fill_rect(fb, fix, state->origin_x + x * state->cell, state->origin_y, 1, state->grid_h * state->cell, grid);
    }
    for (int y = 1; y < state->grid_h; y++) {
        fill_rect(fb, fix, state->origin_x, state->origin_y + y * state->cell, state->grid_w * state->cell, 1, grid);
    }

    fill_rect(
        fb,
        fix,
        state->origin_x + state->food.x * state->cell + 4,
        state->origin_y + state->food.y * state->cell + 4,
        state->cell - 8,
        state->cell - 8,
        food
    );

    for (int i = 0; i < state->snake_len; i++) {
        uint32_t color = (i == state->snake_len - 1) ? snake_head : snake_body;
        fill_rect(
            fb,
            fix,
            state->origin_x + state->snake[i].x * state->cell + 3,
            state->origin_y + state->snake[i].y * state->cell + 3,
            state->cell - 6,
            state->cell - 6,
            color
        );
    }

    int bar_x = 24;
    int bar_y = 18;
    fill_rect(fb, fix, bar_x, bar_y, 16, 16, food);
    for (int i = 0; i < state->score && i < 12; i++) {
        fill_rect(fb, fix, bar_x + 32 + i * 20, bar_y, 14, 16, snake_head);
    }
}

static int apply_direction(struct game_state *state, uint16_t code) {
    int ndx = state->dir_x;
    int ndy = state->dir_y;
    if (code == KEY_W || code == KEY_UP) {
        ndx = 0;
        ndy = -1;
    } else if (code == KEY_S || code == KEY_DOWN) {
        ndx = 0;
        ndy = 1;
    } else if (code == KEY_A || code == KEY_LEFT) {
        ndx = -1;
        ndy = 0;
    } else if (code == KEY_D || code == KEY_RIGHT) {
        ndx = 1;
        ndy = 0;
    } else if (code == KEY_Q || code == KEY_ESC) {
        state->quit = 1;
        return 0;
    } else {
        return 0;
    }

    if (state->snake_len > 1 && ndx == -state->dir_x && ndy == -state->dir_y) {
        return 0;
    }
    state->dir_x = ndx;
    state->dir_y = ndy;
    return 1;
}

static void step_game(struct game_state *state) {
    struct point head = state->snake[state->snake_len - 1];
    struct point next = {.x = head.x + state->dir_x, .y = head.y + state->dir_y};

    if (next.x < 0 || next.x >= state->grid_w || next.y < 0 || next.y >= state->grid_h) {
        state->alive = 0;
        state->quit = 1;
        return;
    }

    int will_grow = point_eq(next, state->food);
    int occupied_len = state->snake_len - (will_grow ? 0 : 1);
    for (int i = 0; i < occupied_len; i++) {
        if (point_eq(state->snake[i], next)) {
            state->alive = 0;
            state->quit = 1;
            return;
        }
    }

    if (!will_grow) {
        memmove(&state->snake[0], &state->snake[1], (size_t)(state->snake_len - 1) * sizeof(struct point));
        state->snake[state->snake_len - 1] = next;
        return;
    }

    if (state->snake_len < MAX_SNAKE_LEN) {
        state->snake[state->snake_len] = next;
        state->snake_len += 1;
    } else {
        memmove(&state->snake[0], &state->snake[1], (size_t)(state->snake_len - 1) * sizeof(struct point));
        state->snake[state->snake_len - 1] = next;
    }
    state->score += 1;
    place_food(state);
}

int main(int argc, char **argv) {
    int scripted = argc > 1 && strcmp(argv[1], "--scripted") == 0;

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

    int key_fd = open_keyboard();
    struct pollfd pfd = {.fd = key_fd, .events = POLLIN};
    struct game_state state;
    init_game(&state, (int)var.xres, (int)var.yres, scripted);
    render_scene(fb, map_len, &fix, &state);

    while (!state.quit) {
        int timeout_ms = scripted ? -1 : 140;
        int ready = poll(&pfd, 1, timeout_ms);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            die("poll");
        }
        int stepped = 0;
        if (ready > 0 && (pfd.revents & POLLIN) != 0) {
            struct input_event events[16];
            ssize_t n = read(key_fd, events, sizeof(events));
            if (n < 0) {
                if (errno == EINTR || errno == EAGAIN) {
                    continue;
                }
                die("read(input)");
            }
            size_t count = (size_t)n / sizeof(struct input_event);
            for (size_t i = 0; i < count; i++) {
                if (events[i].type == EV_KEY && events[i].value == 1) {
                    int changed = apply_direction(&state, events[i].code);
                    if (state.quit) {
                        break;
                    }
                    if (scripted && changed) {
                        step_game(&state);
                        stepped = 1;
                    }
                }
            }
        }
        if (!state.quit && !scripted && !stepped) {
            step_game(&state);
        }
        render_scene(fb, map_len, &fix, &state);
    }

    struct timespec delay = {.tv_sec = 0, .tv_nsec = 150 * 1000 * 1000};
    nanosleep(&delay, NULL);

    uint32_t checksum = rolling_checksum(fb, map_len);
    close(key_fd);
    if (munmap(fb, map_len) < 0) {
        die("munmap(/dev/fb0)");
    }
    close(fb_fd);

    printf(
        "snake-lab score=%d len=%d state=%s checksum=0x%08x\n",
        state.score,
        state.snake_len,
        state.alive ? "quit" : "crash",
        checksum
    );
    return state.alive ? 0 : 3;
}
