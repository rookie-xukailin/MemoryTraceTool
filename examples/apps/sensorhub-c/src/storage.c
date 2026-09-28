/* storage.c — 聚合存储。
 *
 * 深调用链设计（验证栈回溯可读性）：
 *   sensor_poll_all → storage_write → storage_compress → storage_append
 *   四层真实业务帧，工具报告应完整展示这条链。
 *
 * 内存行为：每 4 条记录触发一次压缩，压缩缓冲用完即释放（配对）。
 */
#include "storage.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>

#define RECORD_MAX 2048

typedef struct {
    unsigned char data[RECORD_MAX];
    size_t        len;
} storage_rec_t;

static storage_rec_t *s_ring = NULL;
static unsigned       s_cap = 0;
static unsigned       s_head = 0;
static unsigned       s_count = 0;

void storage_init(unsigned capacity)
{
    s_ring = calloc(capacity, sizeof(storage_rec_t));
    s_cap = capacity;
    s_head = 0;
    s_count = 0;
}

/* 第三层：真正落环形缓冲 */
static void storage_append(const unsigned char *data, size_t len)
{
    if (!s_ring)
        return;
    storage_rec_t *rec = &s_ring[s_head];
    rec->len = (len < RECORD_MAX) ? len : RECORD_MAX;
    memcpy(rec->data, data, rec->len);
    s_head = (s_head + 1) % s_cap;
    if (s_count < s_cap)
        s_count++;
}

/* 第二层：模拟压缩——每 4 条写一次压缩聚合缓冲（malloc/free 配对） */
static void storage_compress(const unsigned char *data, size_t len)
{
    static unsigned tick = 0;
    if (++tick % 4 != 0) {
        storage_append(data, len);
        return;
    }
    /* 压缩聚合：分配 → 简单“压缩”（取样） → 释放 */
    unsigned char *packed = malloc(len / 2 + 16);
    if (packed) {
        for (size_t i = 0; i < len / 2; i++)
            packed[i] = data[i * 2];
        storage_append(packed, len / 2);
        free(packed);
    }
}

/* 第一层：对外写入接口（sensor.c 调用） */
void storage_write(unsigned sensor_id, const unsigned char *data, size_t len)
{
    (void)sensor_id;
    storage_compress(data, len);
}
