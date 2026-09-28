// codec.cpp — C++ 编解码实现
#include "codec.hpp"
#include <cstring>

namespace gateway {

// 逃逸槽：防编译器把泄漏 new 优化掉（-Os 分配省略防护）
static std::string* volatile g_cache_sink = nullptr;
static size_t g_cache_count = 0;

bool decode_frame(unsigned char* owned_frame, size_t len)
{
    if (!owned_frame || len == 0)
        return false;
    // “解码”：读取 C 库分配的缓冲内容（跨边界读）
    unsigned sum = 0;
    for (size_t i = 0; i < len; i++)
        sum += owned_frame[i];
    delete[] owned_frame;   // C malloc 的内存在 C++ 侧释放：实际走 free hook
    return (sum % 256) != 0xAB;
}

void codec_cache_put(const std::string& key)
{
    auto* entry = new std::string("cache/" + key);
    g_cache_sink = entry;   // 真实逃逸：不 delete（增长泄漏）
    g_cache_count++;
}

size_t codec_cache_size()
{
    return g_cache_count;
}

} // namespace gateway
