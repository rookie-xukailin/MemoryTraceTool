// codec.hpp — C++ 编解码层（跨边界所有权 + C++ 泄漏点）
#pragma once
#include <cstddef>
#include <string>

namespace gateway {

// 跨边界所有权：netcore_recv(C 分配的帧) 在这里解码后由 C++ delete 释放。
// 验证：free hook 能找到 C 库建的 entry（同一 malloc/free 配对）。
bool decode_frame(unsigned char* owned_frame, size_t len);

// 【注入 bug】解码缓存每次调用泄漏一个 std::string（operator new）
void codec_cache_put(const std::string& key);

size_t codec_cache_size();

} // namespace gateway
