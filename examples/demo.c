/*
 * Demo: Macro-based integration.
 *
 * Compile: make demo
 * Run:     make run_demo
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MEMORYTRACETOOL_ENABLE
#include "memorytracetool/memorytracetool.h"

static void deliberate_leaks(void)
{
    /* Leak 1: simple malloc, never freed */
    char* buf = malloc(128);
    (void)buf;  /* oops, forgot to free */

    /* Leak 2: allocated and lost */
    int* nums = malloc(10 * sizeof(int));
    /* overwrite before freeing — leak */
    nums = malloc(20 * sizeof(int));
    free(nums);

    /* Leak 3: strdup without free */
    char* msg = strdup("hello memorytracetool");
    printf("msg = %s\n", msg);
    /* forgot free(msg) */
}

static void no_leak(void)
{
    char* tmp = malloc(256);
    free(tmp);

    int* arr = calloc(5, sizeof(int));
    arr = realloc(arr, 10 * sizeof(int));
    free(arr);
}

int main(void)
{
    printf("=== MemoryTraceTool Demo ===\n\n");

    printf("--- no_leak() (should be clean) ---\n");
    no_leak();

    printf("\n--- deliberate_leaks() ---\n");
    deliberate_leaks();

    printf("\nLeak report will print on exit...\n");
    return 0;
}
