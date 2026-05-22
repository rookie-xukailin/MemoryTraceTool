/*
 * Demo: Daemon-based monitoring with web dashboard.
 *
 * Build: make demo_daemon
 * Run:   make run_demo_daemon   (starts daemon + runs this)
 *
 * Then open http://<VM_IP>:8080 in your host browser.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void buggy_function1(void)
{
    /* Leak: malloc without free */
    char* buf = malloc(128);
    snprintf(buf, 128, "leaked data from buggy_function1");
}

static void buggy_function2(void)
{
    /* Leak: allocate and re-assign */
    int* arr = malloc(20 * sizeof(int));
    for (int i = 0; i < 20; i++) arr[i] = i;
    arr = malloc(40 * sizeof(int));  /* loses first allocation */
    free(arr);
}

static void buggy_function3(void)
{
    /* Leak: strdup never freed */
    char* s = strdup("this is a leaked string in function3");
    printf("  buggy_function3: s = %s\n", s);
}

static void clean_function(void)
{
    /* No leak: proper alloc/free */
    char* tmp = malloc(256);
    memset(tmp, 0, 256);
    free(tmp);

    int* nums = calloc(8, sizeof(int));
    nums = realloc(nums, 16 * sizeof(int));
    free(nums);
}

int main(int argc, char** argv)
{
    printf("=== MemoryTraceTool Daemon Demo ===\n\n");
    printf("This process has PID %d\n", getpid());
    printf("It will create several deliberate leaks,\n");
    printf("report them to the daemon, then exit.\n\n");

    if (argc > 1) {
        printf("Running for %d iterations...\n\n", atoi(argv[1]));
        for (int i = 0; i < atoi(argv[1]); i++) {
            clean_function();
            buggy_function1();
            buggy_function2();
            buggy_function3();
        }
    } else {
        clean_function();
        buggy_function1();
        buggy_function2();
        buggy_function3();
    }

    printf("Done. Leaks will be reported on exit.\n");
    return 0;
}
