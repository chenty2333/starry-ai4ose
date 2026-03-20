#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

static pid_t spawn_pause_child(void) {
    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return -1;
    }
    if (child == 0) {
        for (;;) {
            pause();
        }
    }
    return child;
}

static int finish_child(pid_t child, int signo) {
    int status = 0;
    if (kill(child, signo) < 0) {
        perror("kill(cleanup)");
        return 1;
    }
    if (wait_for_status(child, &status, 0) < 0) {
        return 1;
    }
    return 0;
}

static int do_stop_phase(void) {
    pid_t child = spawn_pause_child();
    int status = 0;
    if (child < 0) {
        return 1;
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
    if (finish_child(child, SIGINT) != 0) {
        return 1;
    }
    puts("waitctl-stop-lab");
    return 0;
}

static int do_continue_phase(void) {
    pid_t child = spawn_pause_child();
    int status = 0;
    if (child < 0) {
        return 1;
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
    if (finish_child(child, SIGINT) != 0) {
        return 1;
    }
    puts("waitctl-continue-lab");
    return 0;
}

static int do_reap_phase(void) {
    pid_t child = spawn_pause_child();
    int status = 0;
    if (child < 0) {
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
    puts("waitctl-reap-lab");
    return 0;
}

static int do_all_phase(void) {
    pid_t child = spawn_pause_child();
    int status = 0;
    if (child < 0) {
        return 1;
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

int main(int argc, char **argv) {
    if (argc == 1 || strcmp(argv[1], "all") == 0) {
        return do_all_phase();
    }
    if (strcmp(argv[1], "stop") == 0) {
        return do_stop_phase();
    }
    if (strcmp(argv[1], "continue") == 0) {
        return do_continue_phase();
    }
    if (strcmp(argv[1], "reap") == 0) {
        return do_reap_phase();
    }
    fprintf(stderr, "usage: %s [all|stop|continue|reap]\n", argv[0]);
    return 2;
}
