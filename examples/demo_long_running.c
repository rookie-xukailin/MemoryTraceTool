/*
 * Demo: Long-running server process with signal-triggered leak reporting.
 *
 * Build:  make demo_long_running
 * Run:    LD_LIBRARY_PATH=lib build/demo_long_running
 *
 * While running, send SIGUSR1 to trigger an interim leak report:
 *   kill -USR1 <pid>
 *
 * The daemon (mttd) must be running to receive reports:
 *   build/mttd 8080 &
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#define MEMORYTRACETOOL_ENABLE
#include "memorytracetool/memorytracetool.h"

static volatile sig_atomic_t g_running = 1;

static void on_sigint(int sig) { (void)sig; g_running = 0; }

/* Simulated request handlers that leak memory under certain conditions */

static void handle_login(const char* user)
{
    /* Leak: session token allocated but never stored or freed */
    char* token = malloc(256);
    snprintf(token, 256, "sess_%s_%ld", user, (long)time(NULL));
    printf("  [login]  user=%s, token allocated (%p)\n", user, (void*)token);
}

static void handle_query(const char* sql)
{
    /* Leak: result buffer grows over time */
    static char* cache = NULL;
    size_t len = strlen(sql) + 256;
    cache = malloc(len);
    snprintf(cache, len, "result_for_%s_%ld", sql, (long)time(NULL));
    printf("  [query]  sql=%.30s..., cache=%p\n", sql, (void*)cache);
    /* Old cache pointer lost — cumulative leak */
}

static void handle_upload(const char* filename)
{
    /* No leak: buffer properly freed */
    char* buf = malloc(4096);
    memset(buf, 0xAB, 4096);
    printf("  [upload] file=%s, buffer=%p (will free)\n", filename, (void*)buf);
    free(buf);
}

static void handle_config_reload(void)
{
    /* Leak: strdup without free */
    char* cfg = strdup("{\"max_conn\":100,\"timeout\":30}");
    printf("  [config] reloaded: %s (%p)\n", cfg, (void*)cfg);
}

int main(void)
{
    printf("=== MemoryTraceTool — Long-Running Server Demo ===\n\n");
    printf("PID: %d\n", getpid());
    printf("This process simulates a server that slowly leaks memory.\n");
    printf("Send SIGUSR1 to trigger a leak report:\n");
    printf("  kill -USR1 %d\n", getpid());
    printf("Send SIGINT  to stop:\n");
    printf("  kill -INT  %d\n\n", getpid());

    signal(SIGINT, on_sigint);

    mtt_install_signal_handler();
    printf("Signal handler installed (SIGUSR1 → report to daemon if available).\n\n");

    int cycle = 0;
    const char* users[] = {"alice", "bob", "charlie", "diana", NULL};
    const char* files[] = {"data1.bin", "data2.bin", "data3.bin", NULL};

    while (g_running) {
        cycle++;
        printf("--- Cycle %d ---\n", cycle);

        /* Normal operations — some leak, some don't */
        for (int i = 0; users[i]; i++) {
            handle_login(users[i]);
            usleep(100000);  /* 100ms */
        }

        handle_query("SELECT * FROM events WHERE ts > now() - 3600");
        usleep(200000);

        for (int i = 0; files[i]; i++) {
            handle_upload(files[i]);
            usleep(50000);
        }

        /* Every 5th cycle, reload config (leaks) */
        if (cycle % 5 == 0) {
            handle_config_reload();
        }

        /* Every 10th cycle, print stats */
        if (cycle % 10 == 0) {
            printf("\n  Stats: %zu allocs, %zu frees, %zu leaks, "
                   "%zu bytes current, %zu bytes peak\n\n",
                   mtt_get_alloc_count(), mtt_get_free_count(),
                   mtt_get_leak_count(), mtt_get_current_usage(),
                   mtt_get_peak_usage());
        }

        sleep(2);
    }

    printf("\nShutting down. Final report on exit...\n");
    return 0;
}
