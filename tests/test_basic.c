/*
 * Basic correctness tests.
 *
 * Build & run: make test
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#define MEMORYTRACETOOL_ENABLE
#include "memorytracetool/memorytracetool.h"

static int tests_run  = 0;
static int tests_pass = 0;

#define TEST(name)  do { tests_run++; printf("  %-40s ", name); } while(0)
#define OK()        do { tests_pass++; printf("PASS\n"); } while(0)
#define FAIL(msg)   do { printf("FAIL: %s\n", msg); } while(0)

int main(void)
{
    printf("=== MemoryTraceTool Unit Tests ===\n\n");

    /* Test: free(NULL) is safe */
    TEST("free(NULL) is no-op");
    free(NULL);
    OK();

    /* Test: basic alloc/free */
    TEST("malloc + free");
    char* p = malloc(100);
    assert(p != NULL);
    memset(p, 0xAB, 100);
    free(p);
    OK();

    /* Test: calloc zero-initializes */
    TEST("calloc zero-fill");
    int* arr = calloc(10, sizeof(int));
    assert(arr != NULL);
    int all_zero = 1;
    for (int i = 0; i < 10; i++)
        if (arr[i] != 0) all_zero = 0;
    assert(all_zero);
    free(arr);
    OK();

    /* Test: realloc(NULL, size) == malloc(size) */
    TEST("realloc(NULL, n)");
    int* r1 = realloc(NULL, 40);
    assert(r1 != NULL);
    free(r1);
    OK();

    /* Test: realloc grows */
    TEST("realloc grow");
    int* r2 = malloc(4 * sizeof(int));
    r2[0] = 1; r2[1] = 2; r2[2] = 3; r2[3] = 4;
    r2 = realloc(r2, 8 * sizeof(int));
    assert(r2 != NULL);
    assert(r2[0] == 1 && r2[1] == 2 && r2[2] == 3 && r2[3] == 4);
    free(r2);
    OK();

    /* Test: strdup */
    TEST("strdup");
    char* s = strdup("test string");
    assert(s != NULL);
    assert(strcmp(s, "test string") == 0);
    free(s);
    OK();

    /* Test: stats after all frees */
    TEST("zero leaks after cleanup");
    size_t leaks = mtt_get_leak_count();
    if (leaks == 0) OK();
    else FAIL("expected 0 leaks");

    /* Summary */
    printf("\n---\n");
    printf("Results: %d/%d tests passed\n", tests_pass, tests_run);

    return (tests_pass == tests_run) ? 0 : 1;
}
