#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
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
    int shmid = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
    if (shmid < 0) {
        die("shmget");
    }

    char *addr = shmat(shmid, NULL, 0);
    if (addr == (void *)-1) {
        die("shmat(parent)");
    }
    memcpy(addr, "parent-ready", sizeof("parent-ready"));

    pid_t child = fork();
    if (child < 0) {
        die("fork");
    }
    if (child == 0) {
        expect(strcmp(addr, "parent-ready") == 0, "child did not inherit shared bytes");
        memcpy(addr, "child-updated", sizeof("child-updated"));
        if (shmdt(addr) < 0) {
            die("shmdt(child)");
        }
        _exit(0);
    }

    int status = 0;
    if (waitpid(child, &status, 0) < 0) {
        die("waitpid");
    }
    expect(WIFEXITED(status) && WEXITSTATUS(status) == 0, "child did not exit cleanly");
    expect(strcmp(addr, "child-updated") == 0, "parent did not observe child shared-memory write");

    if (shmctl(shmid, IPC_RMID, NULL) < 0) {
        die("shmctl(IPC_RMID)");
    }
    if (shmdt(addr) < 0) {
        die("shmdt(parent)");
    }

    char *reattach = shmat(shmid, NULL, 0);
    expect(reattach == (void *)-1, "segment was still attachable after IPC_RMID + final detach");
    expect(errno != 0, "shmat after removal did not set errno");

    puts("shm-lab");
    return 0;
}
