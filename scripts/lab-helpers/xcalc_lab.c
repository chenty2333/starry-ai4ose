#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/keysym.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    const char *label;
    char kind;
    int value;
} ButtonDef;

static const ButtonDef BUTTONS[] = {
    {"7", 'd', 7}, {"8", 'd', 8}, {"9", 'd', 9}, {"/", 'o', '/'},
    {"4", 'd', 4}, {"5", 'd', 5}, {"6", 'd', 6}, {"*", 'o', '*'},
    {"1", 'd', 1}, {"2", 'd', 2}, {"3", 'd', 3}, {"-", 'o', '-'},
    {"0", 'd', 0}, {".", '.', 0}, {"=", '=', 0}, {"+", 'o', '+'},
};

enum {
    BUTTON_COLS = 4,
    BUTTON_ROWS = 4,
};

typedef struct {
    Display *display;
    int screen;
    Window window;
    GC gc;
    GC gc_invert;
    XFontStruct *font;
    unsigned long bg;
    unsigned long panel;
    unsigned long text;
    unsigned long accent;
    unsigned long hover;
    unsigned long button;
    int width;
    int height;
    int origin_x;
    int origin_y;
    int button_w;
    int button_h;
    int gap;
    int hover_index;
    double accumulator;
    char pending_op;
    bool reset_display;
    bool has_accumulator;
    bool log_input;
    bool pointer_primed;
    bool pointer_grabbed;
    bool keyboard_grabbed;
    int mouse_fd;
    int pointer_x;
    int pointer_y;
    bool raw_left_down;
    char display_text[64];
} App;

static int button_at(const App *app, int x, int y);

static unsigned long alloc_named_color(Display *display, int screen, const char *name, unsigned long fallback) {
    XColor color;
    XColor exact;

    if (XAllocNamedColor(display, DefaultColormap(display, screen), name, &color, &exact)) {
        return color.pixel;
    }
    return fallback;
}

static void clamp_display(App *app, double value) {
    if (fabs(value) < 1e-12) {
        value = 0.0;
    }
    snprintf(app->display_text, sizeof(app->display_text), "%.10g", value);
}

static void reset_state(App *app) {
    app->accumulator = 0.0;
    app->pending_op = 0;
    app->reset_display = false;
    app->has_accumulator = false;
    strcpy(app->display_text, "0");
}

static double current_value(const App *app) {
    return strtod(app->display_text, NULL);
}

static void push_digit(App *app, char digit) {
    size_t len;

    if (app->reset_display || strcmp(app->display_text, "0") == 0) {
        app->display_text[0] = digit;
        app->display_text[1] = '\0';
        app->reset_display = false;
        return;
    }

    len = strlen(app->display_text);
    if (len + 1 < sizeof(app->display_text)) {
        app->display_text[len] = digit;
        app->display_text[len + 1] = '\0';
    }
}

static void push_dot(App *app) {
    if (app->reset_display) {
        strcpy(app->display_text, "0.");
        app->reset_display = false;
        return;
    }
    if (strchr(app->display_text, '.') == NULL) {
        size_t len = strlen(app->display_text);
        if (len + 1 < sizeof(app->display_text)) {
            app->display_text[len] = '.';
            app->display_text[len + 1] = '\0';
        }
    }
}

static void apply_pending(App *app, double rhs) {
    if (!app->has_accumulator) {
        app->accumulator = rhs;
        app->has_accumulator = true;
        return;
    }
    switch (app->pending_op) {
    case '+':
        app->accumulator += rhs;
        break;
    case '-':
        app->accumulator -= rhs;
        break;
    case '*':
        app->accumulator *= rhs;
        break;
    case '/':
        if (fabs(rhs) < 1e-12) {
            strcpy(app->display_text, "err");
            app->pending_op = 0;
            app->has_accumulator = false;
            app->reset_display = true;
            return;
        }
        app->accumulator /= rhs;
        break;
    default:
        app->accumulator = rhs;
        app->has_accumulator = true;
        break;
    }
    clamp_display(app, app->accumulator);
}

static bool activate_button(App *app, int index) {
    const ButtonDef *button;
    double rhs;

    if (index < 0 || index >= (int)(sizeof(BUTTONS) / sizeof(BUTTONS[0]))) {
        return true;
    }
    button = &BUTTONS[index];

    switch (button->kind) {
    case 'd':
        push_digit(app, (char)('0' + button->value));
        return true;
    case '.':
        push_dot(app);
        return true;
    case 'o':
        rhs = current_value(app);
        apply_pending(app, rhs);
        app->pending_op = (char)button->value;
        app->reset_display = true;
        return true;
    case '=':
        rhs = current_value(app);
        apply_pending(app, rhs);
        app->pending_op = 0;
        app->reset_display = true;
        return true;
    default:
        return true;
    }
}

static void compute_layout(App *app) {
    int pad = 16;
    int top = 96;

    app->gap = 10;
    app->origin_x = pad;
    app->origin_y = top;
    app->button_w = (app->width - pad * 2 - app->gap * (BUTTON_COLS - 1)) / BUTTON_COLS;
    app->button_h = (app->height - top - pad - app->gap * (BUTTON_ROWS - 1)) / BUTTON_ROWS;
}

static void draw_button(App *app, int index, int x, int y, int w, int h) {
    const ButtonDef *button = &BUTTONS[index];
    int text_w;
    int text_x;
    int text_y;

    XSetForeground(app->display, app->gc, index == app->hover_index ? app->hover : app->button);
    XFillRectangle(app->display, app->window, app->gc, x, y, (unsigned int)w, (unsigned int)h);

    XSetForeground(app->display, app->gc, app->text);
    XDrawRectangle(app->display, app->window, app->gc, x, y, (unsigned int)w, (unsigned int)h);
    if (app->font != NULL) {
        text_w = XTextWidth(app->font, button->label, (int)strlen(button->label));
        text_x = x + (w - text_w) / 2;
        text_y = y + (h + app->font->ascent) / 2 - 4;
    } else {
        text_x = x + w / 2 - 4;
        text_y = y + h / 2;
    }
    XDrawString(app->display, app->window, app->gc, text_x, text_y, button->label, (int)strlen(button->label));
}

static void redraw(App *app) {
    int banner_y;
    int display_y;
    int row;
    int col;

    compute_layout(app);
    XSetForeground(app->display, app->gc, app->bg);
    XFillRectangle(app->display, app->window, app->gc, 0, 0, (unsigned int)app->width, (unsigned int)app->height);

    XSetForeground(app->display, app->gc, app->accent);
    XFillRectangle(app->display, app->window, app->gc, 0, 0, (unsigned int)app->width, 42U);
    XSetForeground(app->display, app->gc, app->text);
    XDrawString(app->display, app->window, app->gc, 18, 27, "Starry Lab xcalc", 16);

    XSetForeground(app->display, app->gc, app->panel);
    XFillRectangle(app->display, app->window, app->gc, 16, 54, (unsigned int)(app->width - 32), 28U);
    XSetForeground(app->display, app->gc, app->text);
    banner_y = 72;
    XDrawString(app->display, app->window, app->gc, 26, banner_y, app->display_text, (int)strlen(app->display_text));

    for (row = 0; row < BUTTON_ROWS; ++row) {
        for (col = 0; col < BUTTON_COLS; ++col) {
            int x = app->origin_x + col * (app->button_w + app->gap);
            int y = app->origin_y + row * (app->button_h + app->gap);
            int idx = row * BUTTON_COLS + col;
            draw_button(app, idx, x, y, app->button_w, app->button_h);
        }
    }

    display_y = app->height - 14;
    XSetForeground(app->display, app->gc, app->accent);
    XDrawString(app->display, app->window, app->gc, 18, display_y, "click buttons or type digits/operators", 38);
    XFlush(app->display);
}

static int clamp_int(int value, int low, int high) {
    if (value < low) {
        return low;
    }
    if (value > high) {
        return high;
    }
    return value;
}

static void update_hover_from_pointer(App *app) {
    int index = button_at(app, app->pointer_x, app->pointer_y);

    if (index != app->hover_index) {
        app->hover_index = index;
        redraw(app);
    }
}

static void handle_raw_mouse(App *app) {
    unsigned char buf[48];
    ssize_t n = read(app->mouse_fd, buf, sizeof(buf));

    if (n <= 0) {
        return;
    }
    for (ssize_t i = 0; i + 2 < n; i += 3) {
        unsigned char b0 = buf[i];
        signed char dx = (signed char)buf[i + 1];
        signed char dy = (signed char)buf[i + 2];
        bool left_down = (b0 & 0x1U) != 0;
        int next_x = clamp_int(app->pointer_x + (int)dx, 0, app->width - 1);
        int next_y = clamp_int(app->pointer_y - (int)dy, 0, app->height - 1);

        if (next_x != app->pointer_x || next_y != app->pointer_y) {
            app->pointer_x = next_x;
            app->pointer_y = next_y;
            XWarpPointer(app->display, None, app->window, 0, 0, 0U, 0U, app->pointer_x, app->pointer_y);
            XFlush(app->display);
            update_hover_from_pointer(app);
        }

        if (left_down && !app->raw_left_down) {
            int index = button_at(app, app->pointer_x, app->pointer_y);
            if (app->log_input) {
                printf(
                    "ButtonPress button=1 x=%d y=%d label=%s\n",
                    app->pointer_x,
                    app->pointer_y,
                    index >= 0 ? BUTTONS[index].label : "(none)"
                );
                fflush(stdout);
            }
            if (index >= 0) {
                activate_button(app, index);
                redraw(app);
            }
        }
        app->raw_left_down = left_down;
    }
}

static int button_at(const App *app, int x, int y) {
    int rel_x;
    int rel_y;
    int col;
    int row;

    if (x < app->origin_x || y < app->origin_y) {
        return -1;
    }
    rel_x = x - app->origin_x;
    rel_y = y - app->origin_y;
    col = rel_x / (app->button_w + app->gap);
    row = rel_y / (app->button_h + app->gap);
    if (col < 0 || col >= BUTTON_COLS || row < 0 || row >= BUTTON_ROWS) {
        return -1;
    }
    if (rel_x % (app->button_w + app->gap) >= app->button_w) {
        return -1;
    }
    if (rel_y % (app->button_h + app->gap) >= app->button_h) {
        return -1;
    }
    return row * BUTTON_COLS + col;
}

static bool handle_key(App *app, XKeyEvent *event) {
    KeySym sym = NoSymbol;
    char buf[8];
    int len = XLookupString(event, buf, (int)sizeof(buf), &sym, NULL);

    if (sym == XK_Escape || sym == XK_q || sym == XK_Q) {
        return false;
    }
    if (sym == XK_c || sym == XK_C) {
        reset_state(app);
        redraw(app);
        return true;
    }
    if (sym == XK_Return || sym == XK_KP_Enter) {
        activate_button(app, 14);
        redraw(app);
        return true;
    }
    if (sym == XK_plus || sym == XK_minus || sym == XK_asterisk || sym == XK_slash) {
        int idx = sym == XK_plus ? 15 : sym == XK_minus ? 11 : sym == XK_asterisk ? 7 : 3;
        activate_button(app, idx);
        redraw(app);
        return true;
    }
    if (len == 1 && isdigit((unsigned char)buf[0])) {
        push_digit(app, buf[0]);
        redraw(app);
        return true;
    }
    if (len == 1 && buf[0] == '.') {
        push_dot(app);
        redraw(app);
        return true;
    }
    return true;
}

static void parse_geometry(const char *spec, int *width, int *height, int *pos_x, int *pos_y) {
    int w = *width;
    int h = *height;
    int x = *pos_x;
    int y = *pos_y;

    if (spec == NULL) {
        return;
    }
    if (sscanf(spec, "%dx%d+%d+%d", &w, &h, &x, &y) >= 2) {
        *width = w;
        *height = h;
        *pos_x = x;
        *pos_y = y;
    }
}

int main(int argc, char **argv) {
    App app;
    int i;
    int pos_x = 40;
    int pos_y = 40;
    bool running = true;
    Atom wm_delete;
    int grab_result;
    int keyboard_result;

    memset(&app, 0, sizeof(app));
    app.width = 240;
    app.height = 320;
    app.hover_index = -1;
    reset_state(&app);

    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-geometry") == 0 && i + 1 < argc) {
            parse_geometry(argv[++i], &app.width, &app.height, &pos_x, &pos_y);
        } else if (strcmp(argv[i], "--log-input") == 0) {
            app.log_input = true;
        }
    }

    app.display = XOpenDisplay(NULL);
    if (app.display == NULL) {
        fprintf(stderr, "failed to open DISPLAY\n");
        return 1;
    }

    app.screen = DefaultScreen(app.display);
    app.bg = alloc_named_color(app.display, app.screen, "#111827", BlackPixel(app.display, app.screen));
    app.panel = alloc_named_color(app.display, app.screen, "#0f172a", WhitePixel(app.display, app.screen));
    app.text = alloc_named_color(app.display, app.screen, "#f8fafc", WhitePixel(app.display, app.screen));
    app.accent = alloc_named_color(app.display, app.screen, "#f59e0b", WhitePixel(app.display, app.screen));
    app.hover = alloc_named_color(app.display, app.screen, "#2563eb", WhitePixel(app.display, app.screen));
    app.button = alloc_named_color(app.display, app.screen, "#1f2937", WhitePixel(app.display, app.screen));

    app.window = XCreateSimpleWindow(
        app.display,
        RootWindow(app.display, app.screen),
        pos_x,
        pos_y,
        (unsigned int)app.width,
        (unsigned int)app.height,
        1U,
        app.accent,
        app.bg
    );
    XStoreName(app.display, app.window, "xcalc");
    XSelectInput(
        app.display,
        app.window,
        ExposureMask | KeyPressMask | ButtonPressMask | ButtonReleaseMask | PointerMotionMask
            | EnterWindowMask | LeaveWindowMask | FocusChangeMask | StructureNotifyMask
    );
    wm_delete = XInternAtom(app.display, "WM_DELETE_WINDOW", False);
    XSetWMProtocols(app.display, app.window, &wm_delete, 1);

    app.mouse_fd = open("/dev/input/mice", O_RDONLY | O_NONBLOCK);
    app.pointer_x = app.width / 2;
    app.pointer_y = app.height / 2;
    app.raw_left_down = false;

    app.gc = XCreateGC(app.display, app.window, 0, NULL);
    app.gc_invert = XCreateGC(app.display, app.window, 0, NULL);
    app.font = XLoadQueryFont(app.display, "fixed");
    if (app.font != NULL) {
        XSetFont(app.display, app.gc, app.font->fid);
        XSetFont(app.display, app.gc_invert, app.font->fid);
    }

    XMapWindow(app.display, app.window);
    XFlush(app.display);

    while (running) {
        XEvent event;
        int xfd = ConnectionNumber(app.display);
        struct pollfd pfds[2];
        nfds_t nfds = 1;

        pfds[0].fd = xfd;
        pfds[0].events = POLLIN;
        pfds[0].revents = 0;
        if (app.mouse_fd >= 0) {
            pfds[1].fd = app.mouse_fd;
            pfds[1].events = POLLIN;
            pfds[1].revents = 0;
            nfds = 2;
        }

        if (XPending(app.display) == 0) {
            int poll_ret = poll(pfds, nfds, -1);
            if (poll_ret < 0) {
                if (errno == EINTR) {
                    continue;
                }
                break;
            }
            if (nfds > 1 && (pfds[1].revents & POLLIN) != 0) {
                handle_raw_mouse(&app);
            }
            if (XPending(app.display) == 0) {
                continue;
            }
        }
        XNextEvent(app.display, &event);
        switch (event.type) {
        case Expose:
            if (event.xexpose.count == 0) {
                redraw(&app);
                XRaiseWindow(app.display, app.window);
                XSetInputFocus(app.display, app.window, RevertToParent, CurrentTime);
                if (!app.keyboard_grabbed) {
                    keyboard_result = XGrabKeyboard(
                        app.display,
                        app.window,
                        False,
                        GrabModeAsync,
                        GrabModeAsync,
                        CurrentTime
                    );
                    if (keyboard_result == GrabSuccess) {
                        app.keyboard_grabbed = true;
                    } else if (app.log_input) {
                        printf("KeyboardGrab result=%d\n", keyboard_result);
                        fflush(stdout);
                    }
                }
                if (!app.pointer_grabbed) {
                    grab_result = XGrabPointer(
                        app.display,
                        app.window,
                        False,
                        ButtonPressMask | ButtonReleaseMask | PointerMotionMask,
                        GrabModeAsync,
                        GrabModeAsync,
                        app.window,
                        None,
                        CurrentTime
                    );
                    if (grab_result == GrabSuccess) {
                        app.pointer_grabbed = true;
                    } else if (app.log_input) {
                        printf("PointerGrab result=%d\n", grab_result);
                        fflush(stdout);
                    }
                }
                if (!app.pointer_primed) {
                    XWarpPointer(
                        app.display,
                        None,
                        app.window,
                        0,
                        0,
                        0U,
                        0U,
                        app.width / 2,
                        app.height / 2
                    );
                    XFlush(app.display);
                    app.pointer_primed = true;
                    app.pointer_x = app.width / 2;
                    app.pointer_y = app.height / 2;
                }
            }
            break;
        case ConfigureNotify:
            if (app.width != event.xconfigure.width || app.height != event.xconfigure.height) {
                app.width = event.xconfigure.width;
                app.height = event.xconfigure.height;
                redraw(&app);
            }
            break;
        case MotionNotify: {
            int index = button_at(&app, event.xmotion.x, event.xmotion.y);
            if (app.log_input) {
                printf("MotionNotify x=%d y=%d slot=%d\n", event.xmotion.x, event.xmotion.y, index);
                fflush(stdout);
            }
            if (index != app.hover_index) {
                app.hover_index = index;
                redraw(&app);
            }
            break;
        }
        case ButtonPress: {
            int index = button_at(&app, event.xbutton.x, event.xbutton.y);
            if (app.log_input) {
                printf(
                    "ButtonPress button=%u x=%d y=%d label=%s\n",
                    event.xbutton.button,
                    event.xbutton.x,
                    event.xbutton.y,
                    index >= 0 ? BUTTONS[index].label : "(none)"
                );
                fflush(stdout);
            }
            if (index >= 0) {
                activate_button(&app, index);
                redraw(&app);
            }
            break;
        }
        case KeyPress:
            running = handle_key(&app, &event.xkey);
            break;
        case ClientMessage:
            if ((Atom)event.xclient.data.l[0] == wm_delete) {
                running = false;
            }
            break;
        default:
            break;
        }
    }

    if (app.font != NULL) {
        XFreeFont(app.display, app.font);
    }
    XFreeGC(app.display, app.gc);
    XFreeGC(app.display, app.gc_invert);
    if (app.keyboard_grabbed) {
        XUngrabKeyboard(app.display, CurrentTime);
    }
    if (app.pointer_grabbed) {
        XUngrabPointer(app.display, CurrentTime);
    }
    if (app.mouse_fd >= 0) {
        close(app.mouse_fd);
    }
    XDestroyWindow(app.display, app.window);
    XCloseDisplay(app.display);
    return 0;
}
