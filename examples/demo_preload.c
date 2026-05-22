/*
 * Demo: LD_PRELOAD-based integration.
 *
 * No recompilation needed — just build and run:
 *   make demo_preload
 *   make run_demo_preload
 *
 * MemoryTraceTool hooks malloc/free at runtime via LD_PRELOAD.
 * No include, no macros — plain C.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    printf("=== MemoryTraceTool LD_PRELOAD Demo ===\n\n");

    /* This leaks by itself — memorytracetool catches it without any code changes */
    char* leak = malloc(64);
    strcpy(leak, "this will leak");

    /* Normal allocation, properly freed */
    char* ok = malloc(512);
    free(ok);

    printf("Leak report will print on exit...\n");
    return 0;
}
