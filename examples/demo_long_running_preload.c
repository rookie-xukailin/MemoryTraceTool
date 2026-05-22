/*
 * Demo: Long-running server with LD_PRELOAD leak detection.
 *
 * Build:  make demo_long_running_preload
 * Run:    LD_PRELOAD=lib/libmemorytracetool.so build/demo_long_running_preload
 *
 * While running, send SIGUSR1 to trigger an interim leak report:
 *   kill -USR1 <pid>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

static volatile sig_atomic_t g_running = 1;

static void on_sigint(int sig) { (void)sig; g_running = 0; }

static void handle_session(const char* user)
{
    char* sess = malloc(200);
    snprintf(sess, 200, "session_token_%s_%ld", user, (long)time(NULL));
    printf("  [session] user=%s, token=%p\n", user, (void*)sess);
}

static void handle_cache_update(const char* key)
{
    static char* cache = NULL;
    size_t len = strlen(key) + 128;
    cache = malloc(len);
    snprintf(cache, len, "cached:%s:%ld", key, (long)time(NULL));
    printf("  [cache]   key=%s, cache=%p\n", key, (void*)cache);
}

static void handle_clean_op(void)
{
    char* buf = malloc(1024);
    memset(buf, 0, 1024);
    printf("  [clean]   buffer=%p (freed)\n", (void*)buf);
    free(buf);
}

int main(void)
{
    printf("=== MemoryTraceTool LD_PRELOAD Long-Running Demo ===\n\n");
    printf("PID: %d\n", getpid());
    printf("Send SIGUSR1: kill -USR1 %d\n", getpid());
    printf("Send SIGINT:   kill -INT  %d\n\n", getpid());

    signal(SIGINT, on_sigint);

    int iter = 0;
    while (g_running) {
        iter++;
        printf("--- Iteration %d ---\n", iter);

        handle_session("admin");
        usleep(150000);
        handle_session("guest");
        usleep(150000);
        handle_cache_update("user_list");
        usleep(100000);
        handle_clean_op();
        usleep(100000);

        if (iter % 10 == 0)
            printf("\n  (iteration %d — send SIGUSR1 for report)\n\n", iter);

        sleep(2);
    }

    printf("\nExiting. Final report...\n");
    return 0;
}
