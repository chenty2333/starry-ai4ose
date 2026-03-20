#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void die(const char *what) {
    perror(what);
    _exit(1);
}

static void expect(int cond, const char *what) {
    if (!cond) {
        fprintf(stderr, "%s\n", what);
        _exit(1);
    }
}

int main(void) {
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) {
        die("sysconf(_SC_PAGESIZE)");
    }

    char *region =
        mmap(NULL, (size_t)page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) {
        die("mmap");
    }

    char *first = region;
    char *second = region + page;

    memcpy(first, "parent-page", sizeof("parent-page"));
    memcpy(second, "protect-phase", sizeof("protect-phase"));

    if (mprotect(second, (size_t)page, PROT_READ) < 0) {
        die("mprotect(PROT_READ)");
    }
    expect(strcmp(second, "protect-phase") == 0, "readonly page lost its contents");

    if (mprotect(second, (size_t)page, PROT_READ | PROT_WRITE) < 0) {
        die("mprotect(PROT_READ|PROT_WRITE)");
    }
    memcpy(second, "protect-ok", sizeof("protect-ok"));

    pid_t child = fork();
    if (child < 0) {
        die("fork");
    }
    if (child == 0) {
        expect(strcmp(first, "parent-page") == 0, "child saw wrong inherited bytes");
        expect(strcmp(second, "protect-ok") == 0, "child lost protected page contents");
        memcpy(first, "child-copy", sizeof("child-copy"));
        expect(strcmp(first, "child-copy") == 0, "child failed to update private copy");
        _exit(0);
    }

    int status = 0;
    if (waitpid(child, &status, 0) < 0) {
        die("waitpid");
    }
    expect(WIFEXITED(status) && WEXITSTATUS(status) == 0, "child did not exit cleanly");
    expect(strcmp(first, "parent-page") == 0, "parent page was modified by child write");
    expect(strcmp(second, "protect-ok") == 0, "parent lost writable page contents");

    if (munmap(second, (size_t)page) < 0) {
        die("munmap(second)");
    }
    if (munmap(first, (size_t)page) < 0) {
        die("munmap(first)");
    }

    puts("cow-lab");
    return 0;
}
