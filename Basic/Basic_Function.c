#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

#include "../Include/Memory_Tool_General_Def.h"

void _memory_trace_error(CONST CHAR* file, INT line, CONST CHAR* func, CONST CHAR* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    
    // 获取当前时间
    time_t t = time(NULL);
    struct tm* tm_info = localtime(&t);
    CHAR time_str[26];
    strftime(time_str, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    
    fprintf(stderr, "[%s] [ERROR] %s:%d  %s() - ", time_str, file, line, func);
    vfprintf(stderr, fmt, args);
    
    va_end(args);
}

void _memory_trace_info(CONST CHAR* file, INT line, CONST CHAR* func, CONST CHAR* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    
    // 获取当前时间
    time_t t = time(NULL);
    struct tm* tm_info = localtime(&t);
    CHAR time_str[26];
    strftime(time_str, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    
    fprintf(stderr, "[%s] [INFO] %s:%d  %s() - ", time_str, file, line, func);
    vfprintf(stderr, fmt, args);
    
    va_end(args);
}

void _memory_trace_warning(CONST CHAR* file, INT line, CONST CHAR* func, CONST CHAR* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    
    // 获取当前时间
    time_t t = time(NULL);
    struct tm* tm_info = localtime(&t);
    CHAR time_str[26];
    strftime(time_str, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    
    fprintf(stderr, "[%s] [WARNING] %s:%d  %s() - ", time_str, file, line, func);
    vfprintf(stderr, fmt, args);
    
    va_end(args);
}

INT Basic_Scnprintf(CHAR *pcBuf, size_t ulSize, CHAR *pcFmt, ...)
{
    va_list stArgs;
    INT iLen = 0;

    va_start(stArgs, pcFmt);
    iLen = vsnprintf(pcBuf, ulSize, pcFmt, stArgs);
    va_end(stArgs);
    return (iLen >= (INT)(UINT)ulSize) ? ((INT)(UINT)ulSize -1) : iLen;
}

size_t Bascic_Strlcpy(CHAR *pcDst, CONST CHAR *pcSrc, CONST size_t ulDstSize)
{
    size_t ulSrcLen = 0;
    size_t ulCpyLen = 0;
    
    ulSrcLen = strlen(pcSrc);

    if (0 != ulSrcLen)
    {
        ulCpyLen = (ulSrcLen >= ulDstSize) ? (ulDstSize - 1) : ulSrcLen;
        memcpy(pcDst, pcSrc, ulCpyLen);
        pcDst[ulCpyLen] = '\0';
    }

    return ulCpyLen;
}