/* General macro definitions */


#ifndef _MEMORY_TOOL_GENERAL_DEF_H_
#define _MEMORY_TOOL_GENERAL_DEF_H_

#include <stdint.h> 
#include <stdbool.h>

/* Error Code */
#define MEM_TRACE_TOOL_BASE_CODE   (0x500000)
#define MEM_TRACE_TOOL_SUCCESS                      (0x00)
#define MEM_TRACE_TOOL_ERROR                        (MEM_TRACE_TOOL_BASE_CODE + 0x01)
#define MEM_TRACE_TOOL_ALLOCATE_MEM_FAILED          (MEM_TRACE_TOOL_BASE_CODE + 0x02)
#define MEM_TRACE_TOOL_INVALID_PARAMS_NUM           (MEM_TRACE_TOOL_BASE_CODE + 0x03)
#define MEM_TRACE_TOOL_INVALID_PARAMS_LENGTH        (MEM_TRACE_TOOL_BASE_CODE + 0x04)
#define MEM_TRACE_TOOL_INVALID_PARAMS_CONTENT       (MEM_TRACE_TOOL_BASE_CODE + 0x05)
#define MEM_TARCE_TOOL_USER_GUIDE_HELP              (MEM_TRACE_TOOL_BASE_CODE + 0x06)
#define MEM_TRACE_TOOL_POINTER_IS_NULL              (MEM_TRACE_TOOL_BASE_CODE + 0x07)
#define MEM_TRACE_TOOL_CREATE_TASK_FALIED           (MEM_TRACE_TOOL_BASE_CODE + 0x08)


/* Basic Data Types */
typedef unsigned char       UCHAR;
typedef char                CHAR;
typedef unsigned short      USHORT;
typedef short               SHORT;
typedef unsigned int        UINT;
typedef int                 INT;
typedef unsigned long       ULONG;
typedef long                LONG;
typedef double              DOUBLE;
typedef float               FLOAT;
typedef bool                BOOL_T;

#define STATIC              static
#define VOID                void
#define CONST               const
#define IN
#define OUT
#define INOUT
#define BOOL_TRUE           TRUE
#define BOOL_FALSE          FALSE

/* Tool Limitation */
#define MEM_TRACE_TOOL_MIN_ARGS_NUM         (2)
#define MEM_TRACE_TOOL_MAX_ARGS_NUM         (3)


/* Log Control */
extern void _memory_trace_error(const char* file, int line, const char* func, const char* fmt, ...);
extern void _memory_trace_info(const char* file, int line, const char* func, const char* fmt, ...);
extern void _memory_trace_warning(const char* file, int line, const char* func, const char* fmt, ...);

#define MEMORY_TRACE_ERROR(fmt, ...) \
    _memory_trace_error(__FILE__, __LINE__, __func__, fmt "\n", ##__VA_ARGS__)

#define MEMORY_TRACE_INFO(fmt, ...) \
    _memory_trace_info(__FILE__, __LINE__, __func__, fmt "\n", ##__VA_ARGS__)

#define MEMORY_TRACE_WARNING(fmt, ...) \
    _memory_trace_warning(__FILE__, __LINE__, __func__, fmt "\n", ##__VA_ARGS__)



 
#endif