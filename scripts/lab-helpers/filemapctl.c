#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
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

static void read_exact_at(int fd, off_t offset, char *buf, size_t len) {
    ssize_t n = pread(fd, buf, len, offset);
    if (n < 0) {
        die("pread");
    }
    if ((size_t)n != len) {
        fprintf(stderr, "short pread: expected %zu got %zd\n", len, n);
        _exit(1);
    }
}

static void write_exact_at(int fd, off_t offset, const char *buf, size_t len) {
    ssize_t n = pwrite(fd, buf, len, offset);
    if (n < 0) {
        die("pwrite");
    }
    if ((size_t)n != len) {
        fprintf(stderr, "short pwrite: expected %zu got %zd\n", len, n);
        _exit(1);
    }
}

int main(void) {
    static const char path[] = "/tmp/lab_filemap.bin";
    static const char shared_base[] = "shared-base";
    static const char shared_map[] = "shared-map";
    static const char shared_fd[] = "fd-shared";
    static const char private_base[] = "private-base";
    static const char private_map[] = "private-map";

    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) {
        die("sysconf(_SC_PAGESIZE)");
    }

    int fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (fd < 0) {
        die("open");
    }
    if (ftruncate(fd, (off_t)page * 2) < 0) {
        die("ftruncate");
    }

    write_exact_at(fd, 0, shared_base, sizeof(shared_base));
    write_exact_at(fd, (off_t)page, private_base, sizeof(private_base));

    char *shared =
        mmap(NULL, (size_t)page, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (shared == MAP_FAILED) {
        die("mmap(MAP_SHARED)");
    }
    char *private =
        mmap(NULL, (size_t)page, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, (off_t)page);
    if (private == MAP_FAILED) {
        die("mmap(MAP_PRIVATE)");
    }

    expect(strcmp(shared, shared_base) == 0, "shared mapping did not expose initial file bytes");
    expect(strcmp(private, private_base) == 0, "private mapping did not expose initial file bytes");

    memcpy(shared, shared_map, sizeof(shared_map));
    char buf[64] = {0};
    read_exact_at(fd, 0, buf, sizeof(shared_map));
    expect(strcmp(buf, shared_map) == 0, "shared mapping write was not visible through file I/O");

    write_exact_at(fd, 0, shared_fd, sizeof(shared_fd));
    expect(strcmp(shared, shared_fd) == 0, "file write was not visible through the shared mapping");

    memcpy(private, private_map, sizeof(private_map));
    memset(buf, 0, sizeof(buf));
    read_exact_at(fd, (off_t)page, buf, sizeof(private_base));
    expect(strcmp(buf, private_base) == 0, "private mapping write leaked back into the file");

    if (munmap(private, (size_t)page) < 0) {
        die("munmap(private)");
    }
    if (munmap(shared, (size_t)page) < 0) {
        die("munmap(shared)");
    }
    close(fd);

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        die("reopen");
    }
    memset(buf, 0, sizeof(buf));
    read_exact_at(fd, 0, buf, sizeof(shared_fd));
    expect(strcmp(buf, shared_fd) == 0, "shared file bytes were not preserved after remap/close");
    memset(buf, 0, sizeof(buf));
    read_exact_at(fd, (off_t)page, buf, sizeof(private_base));
    expect(strcmp(buf, private_base) == 0, "private page incorrectly changed backing file bytes");
    close(fd);

    if (unlink(path) < 0) {
        die("unlink");
    }

    puts("filemap-lab");
    return 0;
}
