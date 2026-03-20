#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int wait_for_status(pid_t child, int *status, int options) {
    for (;;) {
        pid_t waited = waitpid(child, status, options);
        if (waited < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("waitpid");
            return -1;
        }
        return 0;
    }
}

int main(void) {
    pid_t child = fork();
    int status = 0;

    if (child < 0) {
        perror("fork");
        return 1;
    }

    if (child == 0) {
        for (;;) {
            pause();
        }
    }

    usleep(200000);
    if (kill(child, SIGTSTP) < 0) {
        perror("kill(SIGTSTP)");
        return 1;
    }
    if (wait_for_status(child, &status, WUNTRACED) < 0) {
        return 1;
    }
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTSTP) {
        fprintf(stderr, "expected WIFSTOPPED(SIGTSTP), got status=0x%x\n", status);
        return 1;
    }

    if (kill(child, SIGCONT) < 0) {
        perror("kill(SIGCONT)");
        return 1;
    }
    if (wait_for_status(child, &status, WCONTINUED) < 0) {
        return 1;
    }
    if (!WIFCONTINUED(status)) {
        fprintf(stderr, "expected WIFCONTINUED, got status=0x%x\n", status);
        return 1;
    }

    if (kill(child, SIGINT) < 0) {
        perror("kill(SIGINT)");
        return 1;
    }
    if (wait_for_status(child, &status, 0) < 0) {
        return 1;
    }
    if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGINT) {
        fprintf(stderr, "expected WIFSIGNALED(SIGINT), got status=0x%x\n", status);
        return 1;
    }

    puts("waitctl-lab");
    return 0;
}
