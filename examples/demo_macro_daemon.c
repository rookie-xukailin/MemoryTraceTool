/*
 * Demo: Macro-mode with daemon reporting.
 *
 * Build:  make demo_macro_daemon
 * Run:    LD_LIBRARY_PATH=lib build/demo_macro_daemon
 *
 * Requires daemon running (make run_demo_daemon starts it).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MEMORYTRACETOOL_ENABLE
#include "memorytracetool/memorytracetool.h"

static void login_handler(void)
{
    /* Leak: user session token never freed */
    char* token = malloc(256);
    snprintf(token, 256, "session_%d_%s", getpid(), "abc123xyz");
    printf("  login_handler: created token but forgot to free\n");
}

static void json_parse_config(void)
{
    /* Leak: JSON value duplicated and lost */
    char* config = strdup("{\"host\":\"0.0.0.0\",\"port\":8080}");
    char* copy   = strdup(config);
    printf("  json_parse: config=%s, copy=%s\n", config, copy);
    free(config);
    /* copy is leaked */
}

static void data_buffer_refresh(void)
{
    /* Leak: buffer re-allocated, old one lost */
    int* buf = malloc(1024);
    for (int i = 0; i < 256; i++) buf[i] = i;
    buf = malloc(2048);  /* original 1024 lost */
    printf("  data_buffer: buffer was re-allocated, old one leaked\n");
    free(buf);
}

static void clean_operation(void)
{
    char* tmp = malloc(512);
    memset(tmp, 0xCC, 512);
    free(tmp);
}

int main(void)
{
    printf("=== MemoryTraceTool Macro + Daemon Demo ===\n\n");
    printf("This process (PID %d) tracks with file:line info.\n", getpid());
    printf("Run 'build/mttd 8080' first, then open browser.\n\n");

    clean_operation();
    login_handler();
    json_parse_config();
    data_buffer_refresh();

    printf("\nDone. Report sent to daemon on exit.\n");
    return 0;
}
