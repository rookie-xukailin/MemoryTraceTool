/*
 * 小量持续泄漏演示 — 用于验证长期监测能力
 *
 * 每秒泄漏10字节，不释放，共运行120秒（2分钟）。
 * 到第120秒时应有约120个10字节条目。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

int main(void)
{
    printf("=== Small Leak Demo ===\n");
    printf("PID: %d\n", (int)getpid());
    printf("Leak: 10 bytes/sec, no free, 120 sec total\n\n");

    for (int i = 0; i < 120; i++) {
        void *p = malloc(10);
        if (p) {
            memset(p, 0xAB, 10);  /* 写入防优化 */
            ((volatile char*)p)[0] = (char)i; /* volatile 防优化 */
        }
        if ((i + 1) % 10 == 0)
            printf("[%3ds] leaked %d x 10B = %d bytes\n",
                   i + 1, i + 1, (i + 1) * 10);
        sleep(1);
    }

    printf("\nDone. 120 allocations of 10B each, none freed.\n");
    printf("Waiting 65s for reporter to do another scan...\n");
    sleep(65);

    return 0;
}
