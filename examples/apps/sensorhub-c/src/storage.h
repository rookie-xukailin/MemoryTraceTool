/* storage.h — 聚合存储（深调用链） */
#ifndef SH_STORAGE_H
#define SH_STORAGE_H

#include <stddef.h>

void storage_init(unsigned capacity);
void storage_write(unsigned sensor_id, const unsigned char *data, size_t len);

#endif
