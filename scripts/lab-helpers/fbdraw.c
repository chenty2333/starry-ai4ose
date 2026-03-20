#include <errno.h>
#include <fcntl.h>
#include <linux/fb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
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
    fill_rect(base, fix, x, y, w, 3, border);
    fill_rect(base, fix, x, y + h - 3, w, 3, border);
    fill_rect(base, fix, x, y, 3, h, border);
    fill_rect(base, fix, x + w - 3, y, 3, h, border);
}

static const uint8_t GLYPH_F[7] = {0x1f, 0x10, 0x1e, 0x10, 0x10, 0x10, 0x10};
static const uint8_t GLYPH_B[7] = {0x1e, 0x11, 0x11, 0x1e, 0x11, 0x11, 0x1e};
static const uint8_t GLYPH_L[7] = {0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1f};
static const uint8_t GLYPH_A[7] = {0x0e, 0x11, 0x11, 0x1f, 0x11, 0x11, 0x11};

static void draw_glyph(
    uint8_t *base,
    const struct fb_fix_screeninfo *fix,
    int x,
    int y,
    const uint8_t glyph[7],
    uint32_t color,
    int scale
) {
    for (int row = 0; row < 7; row++) {
        for (int col = 0; col < 5; col++) {
            if (((glyph[row] >> (4 - col)) & 1u) == 0) {
                continue;
            }
            fill_rect(base, fix, x + col * scale, y + row * scale, scale, scale, color);
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

int main(void) {
    int fd = open("/dev/fb0", O_RDWR);
    if (fd < 0) {
        die("open(/dev/fb0)");
    }

    struct fb_var_screeninfo var;
    struct fb_fix_screeninfo fix;
    if (ioctl(fd, FBIOGET_VSCREENINFO, &var) < 0) {
        die("FBIOGET_VSCREENINFO");
    }
    if (ioctl(fd, FBIOGET_FSCREENINFO, &fix) < 0) {
        die("FBIOGET_FSCREENINFO");
    }

    if (var.bits_per_pixel != 32) {
        fprintf(stderr, "unsupported bpp: %u\n", var.bits_per_pixel);
        return 2;
    }

    size_t map_len = fix.smem_len;
    uint8_t *fb = mmap(NULL, map_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (fb == MAP_FAILED) {
        die("mmap(/dev/fb0)");
    }

    const int width = (int)var.xres;
    const int height = (int)var.yres;
    const int band_h = height / 6;
    const uint32_t bands[6] = {
        pack_rgb(225, 59, 52),
        pack_rgb(244, 143, 52),
        pack_rgb(246, 220, 75),
        pack_rgb(92, 184, 92),
        pack_rgb(52, 152, 219),
        pack_rgb(155, 89, 182),
    };

    memset(fb, 0, map_len);
    for (int i = 0; i < 6; i++) {
        fill_rect(fb, &fix, 0, i * band_h, width, band_h, bands[i]);
    }

    int box_w = width / 3;
    int box_h = height / 4;
    int box_x = (width - box_w) / 2;
    int box_y = (height - box_h) / 2;
    draw_box(
        fb,
        &fix,
        box_x,
        box_y,
        box_w,
        box_h,
        pack_rgb(250, 250, 250),
        pack_rgb(28, 32, 38)
    );

    int scale = box_h / 12;
    if (scale < 3) {
        scale = 3;
    }
    int text_y = box_y + (box_h - 7 * scale) / 2;
    int text_x = box_x + box_w / 8;
    draw_glyph(fb, &fix, text_x, text_y, GLYPH_F, pack_rgb(255, 214, 10), scale);
    draw_glyph(fb, &fix, text_x + 7 * scale, text_y, GLYPH_B, pack_rgb(255, 214, 10), scale);
    draw_glyph(fb, &fix, text_x + 16 * scale, text_y, GLYPH_L, pack_rgb(180, 230, 255), scale);
    draw_glyph(fb, &fix, text_x + 23 * scale, text_y, GLYPH_A, pack_rgb(180, 230, 255), scale);

    uint32_t checksum = rolling_checksum(fb, map_len);
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 200 * 1000 * 1000};
    nanosleep(&delay, NULL);

    printf(
        "fb-lab width=%u height=%u stride=%u bpp=%u checksum=0x%08x\n",
        var.xres,
        var.yres,
        fix.line_length,
        var.bits_per_pixel,
        checksum
    );

    if (munmap(fb, map_len) < 0) {
        die("munmap(/dev/fb0)");
    }
    close(fd);
    return 0;
}
