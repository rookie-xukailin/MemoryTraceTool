/*
 * MemoryTraceTool — ptrace 运行时库注入 + GOT 热修补。
 *
 * 将 libmemorytracetool.so 注入到正在运行的进程中：
 *   1. ptrace ATTACH 暂停目标进程
 *   2. 在目标进程中远程调用 dlopen 加载我们的 .so
 *   3. 解析目标 ELF 的 PLT 重定位表找到 malloc/free/calloc/realloc 的 GOT 表项
 *   4. 将 GOT 表项改写为我们的钩子函数地址
 *   5. 恢复寄存器并 DETACH
 *
 * 支持架构：x86_64 / ARM32 (EABI) / AArch64。
 * 通过预处理器宏在编译时自适应选择 ELF 类型、寄存器布局和调用约定。
 */
#define _GNU_SOURCE
#include "injector.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <elf.h>
#include <stdarg.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/types.h>

/* ======================================================================== *
 *                    架构自适应抽象层                                        *
 * ======================================================================== */

/* ---- 架构检测 ---- */
#if defined(__x86_64__)
  #define MTT_ARCH_X86_64  1
  #define MTT_ARCH_NAME    "x86_64"
#elif defined(__aarch64__)
  #define MTT_ARCH_AARCH64 1
  #define MTT_ARCH_NAME    "aarch64"
#elif defined(__arm__)
  #define MTT_ARCH_ARM     1
  #define MTT_ARCH_NAME    "arm"
#else
  #error "Unsupported architecture for runtime injection"
#endif

/* ---- ELF 原生类型（32 位 vs 64 位） ---- */
#if MTT_ARCH_ARM
  /* 32-bit ARM：使用 Elf32 类型，PLT 重定位用 Elf32_Rel（无 r_addend） */
  typedef Elf32_Ehdr  Elf_Native_Ehdr;
  typedef Elf32_Shdr  Elf_Native_Shdr;
  typedef Elf32_Phdr  Elf_Native_Phdr;
  typedef Elf32_Sym   Elf_Native_Sym;
  typedef Elf32_Dyn   Elf_Native_Dyn;
  typedef Elf32_Addr  Elf_Native_Addr;
  typedef Elf32_Off   Elf_Native_Off;
  typedef Elf32_Word  Elf_Native_Xword;
  typedef Elf32_Rel   Elf_Native_Rela;   /* ARM JUMP_SLOT 用 Rel，非 Rela */
  #define ELF_NATIVE_R_SYM      ELF32_R_SYM
  #define ELF_NATIVE_R_TYPE     ELF32_R_TYPE
  #define ELF_NATIVE_ST_TYPE    ELF32_ST_TYPE
  #define ELF_NATIVE_JUMP_SLOT  R_ARM_JUMP_SLOT
  #define ELF_NATIVE_CLASS      ELFCLASS32
#else
  /* 64-bit（x86_64 / AArch64）：使用 Elf64 类型 */
  typedef Elf64_Ehdr  Elf_Native_Ehdr;
  typedef Elf64_Shdr  Elf_Native_Shdr;
  typedef Elf64_Phdr  Elf_Native_Phdr;
  typedef Elf64_Sym   Elf_Native_Sym;
  typedef Elf64_Dyn   Elf_Native_Dyn;
  typedef Elf64_Addr  Elf_Native_Addr;
  typedef Elf64_Off   Elf_Native_Off;
  typedef Elf64_Xword Elf_Native_Xword;
  typedef Elf64_Rela  Elf_Native_Rela;   /* x86_64/AArch64 JUMP_SLOT 用 Rela */
  #define ELF_NATIVE_R_SYM      ELF64_R_SYM
  #define ELF_NATIVE_R_TYPE     ELF64_R_TYPE
  #define ELF_NATIVE_ST_TYPE    ELF64_ST_TYPE
  #if MTT_ARCH_AARCH64
    #define ELF_NATIVE_JUMP_SLOT  R_AARCH64_JUMP_SLOT
  #else
    #define ELF_NATIVE_JUMP_SLOT  R_X86_64_JUMP_SLOT
  #endif
  #define ELF_NATIVE_CLASS      ELFCLASS64
#endif

/* ---- ptrace 寄存器结构和寄存器访问 ---- */
#if MTT_ARCH_X86_64
  /* x86_64: struct user_regs_struct，通过 rip/rsp/rax/rdi/rsi 访问 */
  typedef struct user_regs_struct native_regs_t;
  #define REG_PC(r)        ((r).rip)
  #define REG_SP(r)        ((r).rsp)
  #define REG_RET(r)       ((r).rax)
  #define REG_ARG1(r)      ((r).rdi)
  #define REG_ARG2(r)      ((r).rsi)
  #define REG_SET_PC(r,v)  ((r).rip = (v))
  #define REG_SET_SP(r,v)  ((r).rsp = (v))
  #define REG_SET_ARG1(r,v) ((r).rdi = (v))
  #define REG_SET_ARG2(r,v) ((r).rsi = (v))
  #define REG_SET_RET(r,v)  ((r).rax = (v))
  #define REG_SYSCALL_NO(r)  ((r).orig_rax)
  #define REGS_GET(pid, r)   ptrace(PTRACE_GETREGS, (pid), NULL, &(r))
  #define REGS_SET(pid, r)   ptrace(PTRACE_SETREGS, (pid), NULL, &(r))
  /* INT3 单字节，通过掩码嵌入 8 字节 PEEKDATA 的低 byte */
  #define BPKT_INSN         0xCC
  #define BPKT_SIZE         1
  #define BPKT_WRITE(old)   (((unsigned long)(old) & ~0xFFUL) | BPKT_INSN)
  #define BPKT_ADJUST_PC(r) ((r).rip -= BPKT_SIZE)
  /* x86_64: 模拟 CALL 压栈 → 返回地址在栈顶 */
  #define REMOTE_CALL_SETUP(rs, fn, a1, a2, rslot, trap) do { \
      REG_SET_PC(rs, (fn));                                    \
      REG_SET_ARG1(rs, (a1));                                  \
      REG_SET_ARG2(rs, (a2));                                  \
      REG_SET_SP(rs, (rslot));                                 \
      REG_SYSCALL_NO(rs) = (unsigned long)-1;                  \
  } while(0)

#elif MTT_ARCH_AARCH64
  /* AArch64: struct user_regs_struct，通过 regs[0..30]/sp/pc/pstate 访问 */
  typedef struct user_regs_struct native_regs_t;
  #define REG_PC(r)        ((r).pc)
  #define REG_SP(r)        ((r).sp)
  #define REG_RET(r)       ((r).regs[0])
  #define REG_ARG1(r)      ((r).regs[0])
  #define REG_ARG2(r)      ((r).regs[1])
  #define REG_SET_PC(r,v)  ((r).pc = (v))
  #define REG_SET_SP(r,v)  ((r).sp = (v))
  #define REG_SET_ARG1(r,v) ((r).regs[0] = (v))
  #define REG_SET_ARG2(r,v) ((r).regs[1] = (v))
  #define REG_SET_RET(r,v)  ((r).regs[0] = (v))
  #define REG_SYSCALL_NO(r) ((r).regs[8])  /* x8 = syscall 编号 */
  #define REG_SET_LR(r,v)  ((r).regs[30] = (v))
  #define REGS_GET(pid, r)  ptrace(PTRACE_GETREGS, (pid), NULL, &(r))
  #define REGS_SET(pid, r)  ptrace(PTRACE_SETREGS, (pid), NULL, &(r))
  /* BRK #0 = 0xd4200000，4 字节 */
  #define BPKT_INSN         0xd4200000UL
  #define BPKT_SIZE         4
  #define BPKT_WRITE(old)   (((unsigned long)(old) & ~0xFFFFFFFFUL) | BPKT_INSN)
  #define BPKT_ADJUST_PC(r) ((r).pc -= BPKT_SIZE)
  /* AArch64: 通过 LR (x30) 返回，把 trap_addr 写入 LR */
  #define REMOTE_CALL_SETUP(rs, fn, a1, a2, rslot, trap) do { \
      REG_SET_PC(rs, (fn));                                    \
      REG_SET_ARG1(rs, (a1));                                  \
      REG_SET_ARG2(rs, (a2));                                  \
      REG_SET_LR(rs, (trap));                                  \
      REG_SET_SP(rs, (rslot));                                 \
  } while(0)

#elif MTT_ARCH_ARM
  /* ARM32: struct user_regs，通过 uregs[0..17] 数组访问 */
  typedef struct user_regs native_regs_t;
  #define ARM_R0   0
  #define ARM_R1   1
  #define ARM_SP  13
  #define ARM_LR  14
  #define ARM_PC  15
  #define ARM_CPSR 16
  #define REG_PC(r)        ((r).uregs[ARM_PC])
  #define REG_SP(r)        ((r).uregs[ARM_SP])
  #define REG_RET(r)       ((r).uregs[ARM_R0])
  #define REG_ARG1(r)      ((r).uregs[ARM_R0])
  #define REG_ARG2(r)      ((r).uregs[ARM_R1])
  #define REG_SET_PC(r,v)  ((r).uregs[ARM_PC] = (v))
  #define REG_SET_SP(r,v)  ((r).uregs[ARM_SP] = (v))
  #define REG_SET_ARG1(r,v) ((r).uregs[ARM_R0] = (v))
  #define REG_SET_ARG2(r,v) ((r).uregs[ARM_R1] = (v))
  #define REG_SET_RET(r,v)  ((r).uregs[ARM_R0] = (v))
  #define REG_SET_LR(r,v)  ((r).uregs[ARM_LR] = (v))
  #define REG_SYSCALL_NO(r) ((r).uregs[17])  /* ARM_ORIG_r0 */
  #define REGS_GET(pid, r)  ptrace(PTRACE_GETREGS, (pid), NULL, &(r))
  #define REGS_SET(pid, r)  ptrace(PTRACE_SETREGS, (pid), NULL, &(r))
  /* BKPT #0 (ARM mode) = 0xe7f001f0，4 字节 */
  #define BPKT_INSN         0xe7f001f0UL
  #define BPKT_SIZE         4
  #define BPKT_WRITE(old)   ((unsigned long)BPKT_INSN)
  #define BPKT_ADJUST_PC(r) ((r).uregs[ARM_PC] -= BPKT_SIZE)
  /* ARM32: 通过 LR (r14) 返回，把 trap_addr 写入 LR。
   * 根据 fn bit[0] 设置 CPSR.T bit——bit[0]=1 为 Thumb，bit[0]=0 为 ARM。
   * 忽略此位会导致 ARM 指令被当作 Thumb 解码，造成不可预测的 SIGSEGV。 */
  #define REMOTE_CALL_SETUP(rs, fn, a1, a2, rslot, trap) do { \
      unsigned long _fn = (fn);                                \
      if (_fn & 1) {                                           \
          REG_SET_PC(rs, _fn & ~1UL);                          \
          (rs).uregs[ARM_CPSR] |= (1U << 5); /* T=1 Thumb */  \
      } else {                                                 \
          REG_SET_PC(rs, _fn);                                 \
          (rs).uregs[ARM_CPSR] &= ~(1U << 5); /* T=0 ARM */   \
      }                                                        \
      REG_SET_ARG1(rs, (a1));                                  \
      REG_SET_ARG2(rs, (a2));                                  \
      REG_SET_LR(rs, (trap));                                  \
      REG_SET_SP(rs, (rslot));                                 \
  } while(0)
#endif

/* ptrace 读写单位：PEEKDATA/POKEDATA 的本机字长 */
#define PTRACE_WORD_SIZE  sizeof(unsigned long)

/* __RTLD_DLOPEN: glibc 内部标志，标识 dlopen 调用来自 libc 内部（而非用户代码）。
 * 缺少此标志时 _dl_open 可能走错误代码路径，在 ARM32 上触发 SIGSEGV。 */
#define __RTLD_DLOPEN  0x80000000UL

/* ======================================================================== *
 *                           钩取符号列表                                    *
 * ======================================================================== */

const char* g_inject_hook_names[] = {"malloc", "free", "calloc", "realloc", NULL};

/* ---- 辅助: /proc/pid/maps 解析 ---- */

/** 内存映射区域描述 */
typedef struct {
    unsigned long start;
    unsigned long end;
    char          perms[8];
    unsigned long offset;
    char          path[512];
} mem_region_t;

#define MAX_REGIONS 2048

/**
 * 读取 /proc/<pid>/maps，解析所有内存映射区域。
 */
static int read_maps(pid_t pid, mem_region_t* regions, int max)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE* f = fopen(path, "r");
    if (!f) return -1;

    int count = 0;
    char line[1024];
    while (fgets(line, sizeof(line), f) && count < max) {
        mem_region_t* r = &regions[count];
        r->path[0] = '\0';
        int n = sscanf(line, "%lx-%lx %7s %lx %*x:%*x %*d %511[^\n]",
                       &r->start, &r->end, r->perms, &r->offset, r->path);
        if (n >= 4) count++;
    }
    fclose(f);

    if (count >= max) {
        fprintf(stderr, "[DEBUG] WARNING: read_maps hit limit %d, "
                "high-address regions (libc, ld-linux) may be truncated\n", max);
    }
    return count;
}

/**
 * 检查路径是否为 libc（排除 libcap, libcrypt, libcrypto 等以 libc 开头的库）。
 * basename 以 "libc" 开头且下一个字符不是字母 (a-zA-Z)，即可匹配：
 * libc.so.6, libc-2.31.so, libc6.so, libc.so, libc 等变体。
 */
static int is_libc_path(const char* path)
{
    const char* base = strrchr(path, '/');
    if (base) base++; else base = path;
    if (strncmp(base, "libc", 4) != 0) return 0;
    char next = base[4];
    if (next >= 'a' && next <= 'z') return 0;
    if (next >= 'A' && next <= 'Z') return 0;
    return 1;
}

/**
 * 在 maps 中查找包含指定路径的第一个可执行区域。
 * name_hint=NULL 表示主可执行文件。
 */
static const mem_region_t* find_region(const mem_region_t* regions, int count,
                                       const char* name_hint, int is_exec)
{
    for (int i = 0; i < count; i++) {
        if (is_exec && !strchr(regions[i].perms, 'x')) continue;
        if (name_hint) {
            if (strstr(regions[i].path, name_hint))
                return &regions[i];
        } else {
            /* 跳过虚拟映射 [vvar]/[vdso]/[vsyscall] 等不以 '/' 开头的路径，
             * 以及匿名映射（path 为空），避免误匹配为主可执行文件 */
            if (regions[i].path[0] == '[') continue;
            if (regions[i].path[0] && !strstr(regions[i].path, ".so"))
                return &regions[i];
        }
    }
    return NULL;
}

/* ---- 辅助: ELF 符号解析 ---- */

/**
 * 从 ELF 文件中查找指定符号的虚拟地址偏移（相对于 ELF load base）。
 */
static int elf_find_symbol(const char* elf_path, const char* sym_name,
                           unsigned long* out_offset)
{
    FILE* f = fopen(elf_path, "rb");
    if (!f) return -1;

    Elf_Native_Ehdr ehdr;
    if (fread(&ehdr, 1, sizeof(ehdr), f) != sizeof(ehdr)) goto fail;
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) goto fail;
    if (ehdr.e_ident[EI_CLASS] != ELF_NATIVE_CLASS) goto fail;

    /* 读取 section header string table */
    Elf_Native_Shdr shstr_shdr;
    fseek(f, (long)(ehdr.e_shoff + (unsigned long)(ehdr.e_shstrndx) * sizeof(Elf_Native_Shdr)), SEEK_SET);
    if (fread(&shstr_shdr, 1, sizeof(shstr_shdr), f) != sizeof(shstr_shdr)) goto fail;

    char* shstrtab = (char*)malloc(shstr_shdr.sh_size);
    if (!shstrtab) goto fail;
    fseek(f, (long)shstr_shdr.sh_offset, SEEK_SET);
    if (fread(shstrtab, 1, shstr_shdr.sh_size, f) != shstr_shdr.sh_size) {
        free(shstrtab);
        goto fail;
    }

    Elf_Native_Shdr* shdrs = (Elf_Native_Shdr*)malloc(ehdr.e_shnum * sizeof(Elf_Native_Shdr));
    if (!shdrs) { free(shstrtab); goto fail; }
    fseek(f, (long)ehdr.e_shoff, SEEK_SET);
    if (fread(shdrs, 1, ehdr.e_shnum * sizeof(Elf_Native_Shdr), f)
        != ehdr.e_shnum * sizeof(Elf_Native_Shdr)) {
        free(shdrs); free(shstrtab); goto fail;
    }

    Elf_Native_Shdr *symtab_shdr = NULL, *strtab_shdr = NULL;
    Elf_Native_Shdr *dynsym_shdr = NULL, *dynstr_shdr = NULL;
    for (int i = 0; i < ehdr.e_shnum; i++) {
        const char* sname = shstrtab + shdrs[i].sh_name;
        if (shdrs[i].sh_type == SHT_SYMTAB && strcmp(sname, ".symtab") == 0) {
            symtab_shdr = &shdrs[i];
        } else if (shdrs[i].sh_type == SHT_STRTAB && strcmp(sname, ".strtab") == 0) {
            strtab_shdr = &shdrs[i];
        } else if (shdrs[i].sh_type == SHT_DYNSYM && strcmp(sname, ".dynsym") == 0) {
            dynsym_shdr = &shdrs[i];
        } else if (shdrs[i].sh_type == SHT_STRTAB && strcmp(sname, ".dynstr") == 0) {
            dynstr_shdr = &shdrs[i];
        }
    }

    *out_offset = 0;
    int found = 0;

    /* 先查 .dynsym，再查 .symtab */
    for (int table = 0; table < 2 && !found; table++) {
        Elf_Native_Shdr* sym_hdr = (table == 0) ? dynsym_shdr : symtab_shdr;
        Elf_Native_Shdr* str_hdr = (table == 0) ? dynstr_shdr : strtab_shdr;
        if (!sym_hdr || !str_hdr) continue;

        char* strtab_data = (char*)malloc(str_hdr->sh_size);
        if (!strtab_data) continue;
        fseek(f, (long)str_hdr->sh_offset, SEEK_SET);
        if (fread(strtab_data, 1, str_hdr->sh_size, f) != str_hdr->sh_size) {
            free(strtab_data);
            continue;
        }

        int nsyms = (int)(sym_hdr->sh_size / sizeof(Elf_Native_Sym));
        Elf_Native_Sym* syms = (Elf_Native_Sym*)malloc(sym_hdr->sh_size);
        if (!syms) { free(strtab_data); continue; }
        fseek(f, (long)sym_hdr->sh_offset, SEEK_SET);
        if (fread(syms, 1, sym_hdr->sh_size, f) != sym_hdr->sh_size) {
            free(syms); free(strtab_data); continue;
        }

        for (int i = 0; i < nsyms; i++) {
            const char* name = strtab_data + syms[i].st_name;
            if (strcmp(name, sym_name) == 0 && syms[i].st_value != 0
                && syms[i].st_shndx != SHN_UNDEF) {
                *out_offset = (unsigned long)syms[i].st_value;
                found = 1;
                break;
            }
        }
        free(syms);
        free(strtab_data);
    }

    free(shdrs);
    free(shstrtab);
    fclose(f);
    return found ? 0 : -1;

fail:
    fclose(f);
    return -1;
}

/* ---- ptrace 辅助操作 ---- */

/**
 * 安全写入目标进程内存。
 *
 * 以 PTRACE_WORD_SIZE 为单位进行对齐写入，处理部分页写入
 * 和非对齐末尾。跨架构适用 — PTRACE_POKEDATA 在 32 位系统上
 * 写 4 字节，64 位系统上写 8 字节。
 */
static int ptrace_write_mem(pid_t pid, unsigned long addr,
                            const void* data, size_t len)
{
    const char* bytes = (const char*)data;
    size_t nwords = (len + PTRACE_WORD_SIZE - 1) / PTRACE_WORD_SIZE;

    for (size_t i = 0; i < nwords; i++) {
        unsigned long word = 0;
        size_t off = i * PTRACE_WORD_SIZE;
        size_t remain = len - off;
        if (remain >= PTRACE_WORD_SIZE) {
            /* 使用 memcpy 避免非对齐访问 UB（ARM 上可能 SIGBUS） */
            memcpy(&word, bytes + off, PTRACE_WORD_SIZE);
        } else {
            /* 部分字：先读出现有内容，再拼接 */
            long existing = ptrace(PTRACE_PEEKDATA, pid,
                                   (void*)(addr + off), NULL);
            if (existing == -1 && errno != 0) return -1;
            memcpy(&word, bytes + off, remain);
            /* 保留原数据的高位部分 */
            memcpy((char*)&word + remain,
                   (char*)&existing + remain,
                   PTRACE_WORD_SIZE - remain);
        }
        if (ptrace(PTRACE_POKEDATA, pid,
                   (void*)(addr + i * PTRACE_WORD_SIZE), (void*)word) == -1)
            return -1;
    }
    return 0;
}

/* ---- 远程函数调用 ---- */

/**
 * 在目标进程中远程调用 fn(arg1, arg2)。
 *
 * 通过操纵目标进程的寄存器和执行流实现：
 *   1. 在 libc 可执行区域末尾写入架构特定的断点指令（trap_addr）
 *   2. 设置目标进程寄存器：PC=fn, ARG1/ARG2 传参，返回地址=trap_addr
 *   3. PTRACE_CONT 执行直到 hit 断点（SIGTRAP）
 *   4. 读取返回值，恢复 trap_addr 原始内容
 *
 * 不同架构的调用约定差异通过 REMOTE_CALL_SETUP 宏抽象：
 *   - x86_64: 模拟 CALL 压栈（返回地址在栈上）
 *   - ARM32/AArch64: 设置 LR 寄存器为 trap_addr
 *
 * @param pid       目标 PID
 * @param fn_addr   目标函数地址
 * @param arg1      第一个参数
 * @param arg2      第二个参数
 * @param trap_addr 存放断点指令的可执行内存地址
 * @param regs      输入: 原始寄存器 / 输出: 调用后寄存器状态
 * @return          0 成功（返回值在 RET 寄存器中），-1 失败
 */
static int ptrace_remote_call(pid_t pid, unsigned long fn_addr,
                              unsigned long arg1, unsigned long arg2,
                              unsigned long trap_addr,
                              native_regs_t* regs)
{
    unsigned long orig_sp = REG_SP(*regs);
    /* 预留 16KB 栈空间供 dlopen 等复杂函数使用 */
    unsigned long ret_slot = orig_sp - 16384;
#if MTT_ARCH_ARM
    /* ARM32 AAPCS: 栈需 8 字节对齐。ARM 用 LR 返回，无需预留返回地址槽。 */
    ret_slot &= ~0x07UL;
#else
    /* x86_64 / AArch64: 栈需 16 字节对齐 */
    ret_slot &= ~0x0FUL;
    ret_slot -= PTRACE_WORD_SIZE; /* 预留返回地址槽 */
#endif

    /* 保存并写入断点指令 */
    long old_trap = ptrace(PTRACE_PEEKDATA, pid, (void*)trap_addr, NULL);
    if (old_trap == -1 && errno != 0) return -1;
    unsigned long trap_word = BPKT_WRITE(old_trap);
    if (ptrace(PTRACE_POKEDATA, pid, (void*)trap_addr,
               (void*)trap_word) == -1)
        return -1;

#if MTT_ARCH_X86_64
    /* x86_64: 把返回地址压入 "栈"（模拟 CALL） */
    long old_ret = ptrace(PTRACE_PEEKDATA, pid, (void*)ret_slot, NULL);
    if (old_ret == -1 && errno != 0) {
        ptrace(PTRACE_POKEDATA, pid, (void*)trap_addr, (void*)old_trap);
        return -1;
    }
    if (ptrace(PTRACE_POKEDATA, pid, (void*)ret_slot,
               (void*)trap_addr) == -1) {
        ptrace(PTRACE_POKEDATA, pid, (void*)trap_addr, (void*)old_trap);
        return -1;
    }
#endif

    /* 构造调用寄存器状态 */
    native_regs_t call_regs = *regs;
    REMOTE_CALL_SETUP(call_regs, fn_addr, arg1, arg2, ret_slot, trap_addr);

    if (REGS_SET(pid, call_regs) == -1) {
        ptrace(PTRACE_POKEDATA, pid, (void*)trap_addr, (void*)old_trap);
#if MTT_ARCH_X86_64
        ptrace(PTRACE_POKEDATA, pid, (void*)ret_slot, (void*)old_ret);
#endif
        return -1;
    }

    /* 执行目标进程直到遇到断点 */
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
        ptrace(PTRACE_POKEDATA, pid, (void*)trap_addr, (void*)old_trap);
#if MTT_ARCH_X86_64
        ptrace(PTRACE_POKEDATA, pid, (void*)ret_slot, (void*)old_ret);
#endif
        REGS_SET(pid, *regs); /* 尝试恢复原始寄存器 */
        return -1;
    }

    int status;
    if (waitpid(pid, &status, 0) == -1) {
        ptrace(PTRACE_POKEDATA, pid, (void*)trap_addr, (void*)old_trap);
#if MTT_ARCH_X86_64
        ptrace(PTRACE_POKEDATA, pid, (void*)ret_slot, (void*)old_ret);
#endif
        return -1;
    }

    fprintf(stderr, "[DEBUG] remote_call wait: status=0x%x", status);
    if (WIFEXITED(status)) fprintf(stderr, " EXITED(%d)", WEXITSTATUS(status));
    if (WIFSIGNALED(status)) fprintf(stderr, " SIGNALED(%s)", strsignal(WTERMSIG(status)));
    if (WIFSTOPPED(status)) fprintf(stderr, " STOPPED(%s)", strsignal(WSTOPSIG(status)));
    fprintf(stderr, "\n");

    /* 恢复原始 trap 和栈数据 */
    ptrace(PTRACE_POKEDATA, pid, (void*)trap_addr, (void*)old_trap);
#if MTT_ARCH_X86_64
    ptrace(PTRACE_POKEDATA, pid, (void*)ret_slot, (void*)old_ret);
#endif

    /* 读取返回后的寄存器状态 */
    if (REGS_GET(pid, *regs) == -1) return -1;

    fprintf(stderr, "[DEBUG] remote_call result: PC=0x%lx RET=0x%lx\n",
            (unsigned long)REG_PC(*regs), (unsigned long)REG_RET(*regs));

    /* 必须是 SIGTRAP 才算成功 */
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        fprintf(stderr, "[DEBUG] Remote call failed: status=0x%x, sig=%d\n",
                status, WIFSTOPPED(status) ? WSTOPSIG(status) : -1);
        return -1;
    }

    /* 断点后 PC 指向断点指令之后，回退到断点处 */
    BPKT_ADJUST_PC(*regs);

    return 0;
}

/* ---- GOT 修补 ---- */

/** 将动态段的虚拟地址转换为文件偏移（遍历 PT_LOAD 程序头） */
static long vaddr_to_file_off(const Elf_Native_Phdr* phdrs, int phnum,
                              unsigned long vaddr)
{
    for (int i = 0; i < phnum; i++) {
        if (phdrs[i].p_type == PT_LOAD &&
            vaddr >= phdrs[i].p_vaddr &&
            vaddr < phdrs[i].p_vaddr + phdrs[i].p_filesz) {
            return (long)(phdrs[i].p_offset + (vaddr - phdrs[i].p_vaddr));
        }
    }
    return -1;
}

/**
 * 解析目标可执行文件 ELF PLT 重定位表，用钩子函数地址覆盖 GOT 槽位。
 *
 * 支持 x86_64、ARM32、AArch64 的 ELF 格式和 PLT 重定位类型。
 * ARM32 上 JUMP_SLOT 使用 Elf32_Rel（无 r_addend 字段），
 * 与其他架构使用的 Rela 不同，已通过 Elf_Native_Rela typedef 统一。
 */
static int patch_got_entries(pid_t pid, const char* exe_path,
                             unsigned long exe_base,
                             const unsigned long hook_addrs[4],
                             char* names_out, size_t names_size)
{
    FILE* f = fopen(exe_path, "rb");
    if (!f) return -1;

    Elf_Native_Ehdr ehdr;
    if (fread(&ehdr, 1, sizeof(ehdr), f) != sizeof(ehdr)) { fclose(f); return -1; }
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) { fclose(f); return -1; }
    if (ehdr.e_ident[EI_CLASS] != ELF_NATIVE_CLASS) { fclose(f); return -1; }

    int is_pie = (ehdr.e_type == ET_DYN);

    Elf_Native_Phdr* phdrs = (Elf_Native_Phdr*)malloc(ehdr.e_phnum * sizeof(Elf_Native_Phdr));
    if (!phdrs) { fclose(f); return -1; }
    fseek(f, (long)ehdr.e_phoff, SEEK_SET);
    if (fread(phdrs, 1, ehdr.e_phnum * sizeof(Elf_Native_Phdr), f)
        != ehdr.e_phnum * sizeof(Elf_Native_Phdr)) {
        free(phdrs); fclose(f); return -1;
    }

    unsigned long dyn_filesz = 0;
    long dyn_file_off = -1;

    for (int i = 0; i < ehdr.e_phnum; i++) {
        if (phdrs[i].p_type == PT_DYNAMIC) {
            dyn_filesz = (unsigned long)phdrs[i].p_filesz;
            dyn_file_off = (long)phdrs[i].p_offset;
            break;
        }
    }
    if (dyn_file_off < 0) { free(phdrs); fclose(f); return -1; }

    int ndyns = (int)(dyn_filesz / sizeof(Elf_Native_Dyn));
    Elf_Native_Dyn* dyns = (Elf_Native_Dyn*)malloc(dyn_filesz);
    if (!dyns) { free(phdrs); fclose(f); return -1; }
    fseek(f, dyn_file_off, SEEK_SET);
    if (fread(dyns, 1, dyn_filesz, f) != dyn_filesz) {
        free(dyns); free(phdrs); fclose(f); return -1;
    }

    unsigned long jmprel   = 0;
    unsigned long pltrelsz = 0;
    unsigned long symtab   = 0;
    unsigned long strtab   = 0;

    for (int i = 0; i < ndyns; i++) {
        switch (dyns[i].d_tag) {
        case DT_JMPREL:   jmprel   = (unsigned long)dyns[i].d_un.d_val; break;
        case DT_PLTRELSZ: pltrelsz = (unsigned long)dyns[i].d_un.d_val; break;
        case DT_SYMTAB:   symtab   = (unsigned long)dyns[i].d_un.d_val; break;
        case DT_STRTAB:   strtab   = (unsigned long)dyns[i].d_un.d_val; break;
        }
    }

    if (!jmprel || !pltrelsz || !symtab || !strtab) {
        free(dyns); free(phdrs); fclose(f); return -1;
    }

    /* 将动态段的虚拟地址转换为文件偏移 */
    long rela_off = vaddr_to_file_off(phdrs, ehdr.e_phnum, jmprel);
    if (rela_off < 0) { free(dyns); free(phdrs); fclose(f); return -1; }
    int nrelocs = (int)(pltrelsz / sizeof(Elf_Native_Rela));

    long sym_off = vaddr_to_file_off(phdrs, ehdr.e_phnum, symtab);
    if (sym_off < 0) { free(dyns); free(phdrs); fclose(f); return -1; }
    long str_off = vaddr_to_file_off(phdrs, ehdr.e_phnum, strtab);
    if (str_off < 0) { free(dyns); free(phdrs); fclose(f); return -1; }

    /* 读取 .dynsym 真实大小 */
    size_t sym_size = 0;
    {
        Elf_Native_Shdr* shdrs = (Elf_Native_Shdr*)malloc(ehdr.e_shnum * sizeof(Elf_Native_Shdr));
        if (shdrs) {
            fseek(f, (long)ehdr.e_shoff, SEEK_SET);
            if (fread(shdrs, 1, ehdr.e_shnum * sizeof(Elf_Native_Shdr), f)
                == ehdr.e_shnum * sizeof(Elf_Native_Shdr)) {
                for (int i = 0; i < ehdr.e_shnum; i++) {
                    if (shdrs[i].sh_type == SHT_DYNSYM) {
                        sym_size = (size_t)shdrs[i].sh_size;
                        break;
                    }
                }
            }
            free(shdrs);
        }
    }
    if (sym_size == 0) {
        if (str_off > sym_off && (size_t)(str_off - sym_off) < 16 * 1024 * 1024)
            sym_size = (size_t)(str_off - sym_off);
        else
            sym_size = 65536 * sizeof(Elf_Native_Sym);
    }

    fseek(f, 0, SEEK_END);
    long file_sz = ftell(f);
    size_t str_size = (size_t)(file_sz - str_off);
    if (str_size > 16 * 1024 * 1024) str_size = 16 * 1024 * 1024;

    char* strtab_data = (char*)malloc(str_size);
    if (!strtab_data) { free(dyns); free(phdrs); fclose(f); return -1; }
    fseek(f, (long)str_off, SEEK_SET);
    if (fread(strtab_data, 1, str_size, f) != str_size) {
        free(strtab_data); free(dyns); free(phdrs); fclose(f); return -1;
    }

    Elf_Native_Sym* syms = (Elf_Native_Sym*)malloc(sym_size);
    if (!syms) { free(strtab_data); free(dyns); free(phdrs); fclose(f); return -1; }
    fseek(f, (long)sym_off, SEEK_SET);
    if (fread(syms, 1, sym_size, f) != sym_size) {
        free(syms); free(strtab_data); free(dyns); free(phdrs); fclose(f); return -1;
    }

    int patched = 0;
    fseek(f, (long)rela_off, SEEK_SET);
    fprintf(stderr, "[DEBUG] patch_got: PIE=%d exe_base=0x%lx nrelocs=%d jmprel=0x%lx\n",
            is_pie, exe_base, nrelocs, jmprel);

    for (int i = 0; i < nrelocs; i++) {
        Elf_Native_Rela rela;
        if (fread(&rela, 1, sizeof(rela), f) != sizeof(rela)) break;

        if (ELF_NATIVE_R_TYPE(rela.r_info) != ELF_NATIVE_JUMP_SLOT)
            continue;

        unsigned long sym_idx = (unsigned long)ELF_NATIVE_R_SYM(rela.r_info);
        if (sym_idx >= sym_size / sizeof(Elf_Native_Sym)) continue;

        const char* name = strtab_data + syms[sym_idx].st_name;
        if (i < 5) fprintf(stderr, "[DEBUG] PLT[%d]: sym_idx=%lu name=%s r_offset=0x%lx\n",
                           i, sym_idx, name, (unsigned long)rela.r_offset);

        int hook_idx = -1;
        for (int j = 0; j < 4; j++) {
            if (strcmp(name, g_inject_hook_names[j]) == 0) {
                hook_idx = j;
                break;
            }
        }
        if (hook_idx < 0) continue;

        unsigned long got_addr = is_pie
            ? (exe_base + (unsigned long)rela.r_offset)
            : (unsigned long)rela.r_offset;
        unsigned long hook_addr = hook_addrs[hook_idx];

        errno = 0;
        /* GOT 可写性预检查：先 PTRACE_PEEKDATA 读取当前值，验证地址有效 */
        unsigned long old_got_val = 0;
        errno = 0;
        old_got_val = ptrace(PTRACE_PEEKDATA, pid, (void*)got_addr, NULL);
        if (old_got_val == (unsigned long)-1 && errno != 0) {
            fprintf(stderr, "[DEBUG] POKEDATA %s: PEEKDATA failed got=0x%lx errno=%d (%s)\n",
                    name, got_addr, errno, strerror(errno));
            continue;
        }
        if (ptrace(PTRACE_POKEDATA, pid, (void*)got_addr,
                   (void*)hook_addr) != -1) {
            fprintf(stderr, "[DEBUG] POKEDATA %s: got=0x%lx hook=0x%lx OK\n",
                    name, got_addr, hook_addr);
            if (names_out && names_size > 0) {
                size_t cur = strlen(names_out);
                size_t nlen = strlen(name);
                size_t need = cur + (cur > 0 ? 1 : 0) + nlen;
                if (need < names_size) {
                    if (cur > 0) names_out[cur++] = ',';
                    memcpy(names_out + cur, name, nlen);
                    names_out[cur + nlen] = '\0';
                }
            }
            patched++;
        } else {
            fprintf(stderr, "[DEBUG] POKEDATA %s: got=0x%lx hook=0x%lx FAIL errno=%d(%s)\n",
                    name, got_addr, hook_addr, errno, strerror(errno));
        }
    }

    free(syms);
    free(strtab_data);
    free(dyns);
    free(phdrs);
    fclose(f);
    return patched;
}

/* ---- 主入口 ---- */

/** 设置 inject_result_t 错误返回 */
static void set_error(inject_result_t* res, inject_status_t st,
                      const char* fmt, ...)
    __attribute__((format(printf, 3, 4)));

static void set_error(inject_result_t* res, inject_status_t st,
                      const char* fmt, ...)
{
    memset(res, 0, sizeof(*res));
    res->pid = 0;
    res->status = st;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(res->err_msg, sizeof(res->err_msg), fmt, ap);
    va_end(ap);
}

/**
 * 将 libmemorytracetool.so 注入到目标进程并修补其 GOT。
 *
 * @param pid       目标进程 PID
 * @param lib_path  要注入的 .so 文件路径
 * @return          注入结果
 */
inject_result_t inject_library(pid_t pid, const char* lib_path)
{
    inject_result_t res;
    memset(&res, 0, sizeof(res));
    res.pid = pid;

    /* 验证 PID 存在 */
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d", pid);
    if (access(proc_path, F_OK) != 0) {
        set_error(&res, INJECT_ERR_NOTFOUND,
                  "PID %d not found in /proc", pid);
        return res;
    }

    /* 获取 lib_path 的绝对路径 */
    char abs_lib[512];
    if (lib_path[0] != '/') {
        if (!realpath(lib_path, abs_lib)) {
            set_error(&res, INJECT_ERR_DLOPEN,
                      "Cannot resolve library path: %s", lib_path);
            return res;
        }
    } else {
        strncpy(abs_lib, lib_path, sizeof(abs_lib) - 1);
        abs_lib[sizeof(abs_lib) - 1] = '\0';
    }

    /* ---- Step 1: ATTACH ---- */
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        if (errno == EPERM) {
            set_error(&res, INJECT_ERR_PERM,
                      "Permission denied. Run as root or: "
                      "echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope");
        } else if (errno == ESRCH) {
            set_error(&res, INJECT_ERR_NOTFOUND,
                      "Process %d no longer exists", pid);
        } else {
            set_error(&res, INJECT_ERR_ATTACH,
                      "ptrace ATTACH failed: %s", strerror(errno));
        }
        return res;
    }

    int status;
    if (waitpid(pid, &status, 0) == -1) {
        set_error(&res, INJECT_ERR_ATTACH,
                  "waitpid after ATTACH failed: %s", strerror(errno));
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return res;
    }

    if (!WIFSTOPPED(status)) {
        set_error(&res, INJECT_ERR_CRASH,
                  "Target process did not stop after ATTACH (status=%d)", status);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return res;
    }

    /* ---- Step 2: 保存原始寄存器 ---- */
    native_regs_t saved_regs;
    if (REGS_GET(pid, saved_regs) == -1) {
        set_error(&res, INJECT_ERR_ATTACH,
                  "PTRACE_GETREGS failed: %s", strerror(errno));
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return res;
    }

    /* ---- Step 3: 查找目标 libc 基址 ---- */
    mem_region_t regions[MAX_REGIONS];
    int nregions = read_maps(pid, regions, MAX_REGIONS);
    if (nregions <= 0) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        set_error(&res, INJECT_ERR_ATTACH,
                  "Cannot read /proc/%d/maps", pid);
        return res;
    }
    fprintf(stderr, "[DEBUG] Target PID %d has %d memory regions\n", pid, nregions);

    /* 查找 libc 可执行区域：用 is_libc_path 精确匹配 libc.so/libc-，
     * 避免 strstr(...,"libc") 误匹配 libcap, libcrypt, libcrypto 等。 */
    const mem_region_t* libc_region = NULL;
    for (int i = 0; i < nregions; i++) {
        if (is_libc_path(regions[i].path) && strchr(regions[i].perms, 'x')) {
            libc_region = &regions[i];
            break;
        }
    }
    if (!libc_region) {
        for (int i = 0; i < nregions; i++) {
            if (is_libc_path(regions[i].path) && strchr(regions[i].perms, 'x')) {
                libc_region = &regions[i];
                break;
            }
        }
    }
    if (!libc_region) {
        fprintf(stderr, "[DEBUG] Cannot find libc. Target PID %d maps:\n", pid);
        for (int i = 0; i < nregions; i++) {
            fprintf(stderr, "[DEBUG]   0x%lx-0x%lx %s %s\n",
                    regions[i].start, regions[i].end,
                    regions[i].perms, regions[i].path);
        }
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        set_error(&res, INJECT_ERR_DLOPEN,
                  "Cannot find libc in /proc/%d/maps", pid);
        return res;
    }

    /* trap_addr 放在 libc 可执行区域末尾 */
    unsigned long trap_addr = (libc_region->end - 16) & ~((unsigned long)15);

    /* ELF 符号偏移是相对于 load bias（第一个映射起始地址），而非可执行区域起始地址。
     * ARM32 上 libc 的第一个映射通常是 r--p，与 r-xp 地址不同；
     * 用可执行区域起始地址计算 target_dlopen 会导致 SIGSEGV。 */
    unsigned long libc_base = libc_region->start;
    for (int i = 0; i < nregions; i++) {
        if (is_libc_path(regions[i].path) && regions[i].start < libc_base) {
            libc_base = regions[i].start;
        }
    }
    fprintf(stderr, "[DEBUG] target libc path: %s\n", libc_region->path);
    fprintf(stderr, "[DEBUG] libc load_bias=0x%lx r-xp=0x%lx-0x%lx trap_addr=0x%lx\n",
            libc_base, libc_region->start, libc_region->end, trap_addr);

    /* 通过自身 dlsym 计算目标进程中 __libc_dlopen_mode 的地址。
     * __libc_dlopen_mode 是 glibc 内部函数，ptrace 远程注入的标准入口；
     * 若不可用则回退到 dlopen（部分旧版或非 glibc 系统）。 */
    void* our_dlopen = dlsym(RTLD_DEFAULT, "__libc_dlopen_mode");
    if (!our_dlopen) {
        our_dlopen = dlsym(RTLD_DEFAULT, "dlopen");
    }
    if (!our_dlopen) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        set_error(&res, INJECT_ERR_DLOPEN,
                  "Cannot find __libc_dlopen_mode or dlopen in own process");
        return res;
    }

    unsigned long our_libc_base = 0;
    {
        mem_region_t self_regions[MAX_REGIONS];
        int nself = read_maps(getpid(), self_regions, MAX_REGIONS);
        for (int i = 0; i < nself; i++) {
            /* 找最低地址的 libc 映射（load bias），ELF 符号偏移以此为基准 */
            if (is_libc_path(self_regions[i].path)) {
                if (our_libc_base == 0 || self_regions[i].start < our_libc_base) {
                    our_libc_base = self_regions[i].start;
                }
            }
        }
    }
    unsigned long dlopen_offset = (unsigned long)our_dlopen - our_libc_base;
    unsigned long target_dlopen = libc_base + dlopen_offset;
    fprintf(stderr, "[DEBUG] our_dlopen=%p our_libc=0x%lx dlopen_off=0x%lx target_dlopen=0x%lx\n",
            our_dlopen, our_libc_base, dlopen_offset, target_dlopen);

    /* ---- Step 4: 在目标栈上写库路径 ---- */
    unsigned long str_addr = REG_SP(saved_regs) - 32768;
#if MTT_ARCH_ARM
    str_addr &= ~0x07UL;
#else
    str_addr &= ~0x0FUL;
#endif

    fprintf(stderr, "[DEBUG] orig_sp=0x%lx str_addr=0x%lx abs_lib=%s\n",
            (unsigned long)REG_SP(saved_regs), str_addr, abs_lib);

    size_t path_len = strlen(abs_lib) + 1;
    if (ptrace_write_mem(pid, str_addr, abs_lib, path_len) == -1) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        set_error(&res, INJECT_ERR_DLOPEN,
                  "Cannot write library path to target memory");
        return res;
    }

    /* ---- Step 5: 远程调用 __libc_dlopen_mode ----
     * RTLD_NOW 强制立即符号解析，确保加载失败时错误信息可追溯。 */
    native_regs_t call_regs = saved_regs;
    unsigned long dl_mode = (unsigned long)RTLD_NOW;
    if (ptrace_remote_call(pid, target_dlopen, str_addr,
                           dl_mode,
                           trap_addr, &call_regs) != 0) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        set_error(&res, INJECT_ERR_CRASH,
                  "Target process crashed or exited during dlopen call");
        return res;
    }

    unsigned long lib_handle = (unsigned long)REG_RET(call_regs);
    if (lib_handle == 0) {
        REGS_SET(pid, saved_regs);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        set_error(&res, INJECT_ERR_DLOPEN,
                  "dlopen(%s) returned NULL in target. Check library deps.",
                  abs_lib);
        return res;
    }

    /* ---- Step 6: 找到注入库中钩子函数地址 ---- */
    nregions = read_maps(pid, regions, MAX_REGIONS);
    const mem_region_t* our_lib_load = NULL;  /* 最低地址映射 = ELF load bias */
    const mem_region_t* our_lib = NULL;       /* 可执行映射 */
    for (int i = 0; i < nregions; i++) {
        if (strstr(regions[i].path, "libmemorytracetool")) {
            if (!our_lib_load) our_lib_load = &regions[i];
            if (!our_lib || !strchr(our_lib->perms, 'x'))
                our_lib = &regions[i];
            if (strchr(regions[i].perms, 'x')) {
                our_lib = &regions[i];
                break;
            }
        }
    }
    if (!our_lib || !our_lib_load) {
        REGS_SET(pid, saved_regs);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        set_error(&res, INJECT_ERR_DLOPEN,
                  "Library loaded but not found in /proc/%d/maps", pid);
        return res;
    }
    unsigned long so_base = our_lib_load->start;
    fprintf(stderr, "[DEBUG] .so load_bias=0x%lx r-xp_start=0x%lx\n",
            so_base, our_lib->start);
    res.lib_base = so_base;

    /* ---- Step 6.5: 修复 raw_* 函数指针 ----
     * 动态查找 raw_malloc/raw_free/raw_calloc 在 .so 中的偏移，
     * 然后用已知的 libc 基址差值写入目标进程的正确 libc 函数地址。 */
    {
        unsigned long raw_malloc_off = 0, raw_free_off = 0, raw_calloc_off = 0;
        if (elf_find_symbol(abs_lib, "raw_malloc", &raw_malloc_off) != 0 ||
            elf_find_symbol(abs_lib, "raw_free",   &raw_free_off)   != 0 ||
            elf_find_symbol(abs_lib, "raw_calloc", &raw_calloc_off) != 0) {
            fprintf(stderr, "[DEBUG] WARNING: cannot find raw_* symbols in .so, "
                    "injected process may crash\n");
        } else {
            unsigned long real_malloc = 0, real_free = 0, real_calloc = 0;
            /* 使用显式 libc 句柄解析符号，避免 dlsym(RTLD_DEFAULT) 在
             * injector 自身被 LD_PRELOAD 时返回钩子函数的地址。
             * RTLD_NOLOAD 确保使用已加载的 libc，不会重新加载。 */
            void* libc_handle = dlopen("libc.so.6", RTLD_LAZY | RTLD_NOLOAD);
            void* sym_malloc = libc_handle ? dlsym(libc_handle, "malloc") : NULL;
            void* sym_free   = libc_handle ? dlsym(libc_handle, "free")   : NULL;
            void* sym_calloc = libc_handle ? dlsym(libc_handle, "calloc") : NULL;
            if (libc_handle) dlclose(libc_handle);

            if (our_libc_base && sym_malloc)
                real_malloc = libc_base + ((unsigned long)sym_malloc - our_libc_base);
            if (our_libc_base && sym_free)
                real_free   = libc_base + ((unsigned long)sym_free - our_libc_base);
            if (our_libc_base && sym_calloc)
                real_calloc = libc_base + ((unsigned long)sym_calloc - our_libc_base);

            if (real_malloc && real_free && real_calloc) {
                ptrace(PTRACE_POKEDATA, pid,
                       (void*)(so_base + raw_malloc_off), (void*)real_malloc);
                ptrace(PTRACE_POKEDATA, pid,
                       (void*)(so_base + raw_free_off),   (void*)real_free);
                ptrace(PTRACE_POKEDATA, pid,
                       (void*)(so_base + raw_calloc_off), (void*)real_calloc);
                fprintf(stderr, "[DEBUG] Fixed raw_*: malloc=0x%lx free=0x%lx calloc=0x%lx\n",
                        real_malloc, real_free, real_calloc);
            } else {
                fprintf(stderr, "[DEBUG] WARNING: cannot resolve raw_* in libc\n");
            }
        }
    }

    /* ---- Step 7: 查找钩子符号在 .so 中的偏移 ---- */
    unsigned long hook_addrs[4] = {0};
    const char* hook_names[4] = {"malloc", "free", "calloc", "realloc"};
    int hooks_found = 0;
    for (int i = 0; i < 4; i++) {
        unsigned long off = 0;
        if (elf_find_symbol(abs_lib, hook_names[i], &off) == 0) {
            hook_addrs[i] = so_base + off;
            hooks_found++;
        }
    }
    if (hooks_found < 2) {
        REGS_SET(pid, saved_regs);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        set_error(&res, INJECT_ERR_GOT,
                  "Found only %d/4 hook symbols in injected library", hooks_found);
        return res;
    }

    /* ---- Step 8: GOT 修补 ---- */
    char exe_link[64];
    snprintf(exe_link, sizeof(exe_link), "/proc/%d/exe", pid);
    char exe_path[512];
    ssize_t exe_len = readlink(exe_link, exe_path, sizeof(exe_path) - 1);
    if (exe_len <= 0) {
        REGS_SET(pid, saved_regs);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        set_error(&res, INJECT_ERR_GOT,
                  "Cannot readlink /proc/%d/exe", pid);
        return res;
    }
    exe_path[exe_len] = '\0';

    const mem_region_t* exe_region = find_region(regions, nregions, NULL, 0);
    if (!exe_region) {
        REGS_SET(pid, saved_regs);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        set_error(&res, INJECT_ERR_GOT, "Cannot find main executable mapping");
        return res;
    }
    unsigned long exe_base = exe_region->start;
    fprintf(stderr, "[DEBUG] exe_region: start=0x%lx end=0x%lx path=%s\n",
            exe_region->start, exe_region->end, exe_region->path);

    int patched = patch_got_entries(pid, exe_path, exe_base, hook_addrs,
                                     res.patched_names, sizeof(res.patched_names));
    res.patched_count = patched;

    /* 注意：不在此处远程调用 mtt_ensure_init()。
     * ptrace 远程调用上下文中执行 mtt_ensure_init 在 ARM32 上会触发 SIGSEGV，
     * 原因是该函数内部调用 pthread_create / fprintf 等，在远程调用栈上不安全。
     * 库设计为懒初始化：目标进程下一次调用 malloc 时，钩子自然触发
     * mtt_ensure_init → mtt_start_periodic_report → 发送 HELLO 到 daemon。 */

    /* ---- Step 9: 恢复并分离 ---- */
    REGS_SET(pid, saved_regs);

    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        set_error(&res, INJECT_ERR_ATTACH,
                  "PTRACE_DETACH failed: %s (injection may still be active)",
                  strerror(errno));
        return res;
    }

    if (patched == 0) {
        res.status = INJECT_ERR_GOT;
        snprintf(res.err_msg, sizeof(res.err_msg),
                 "Library loaded at 0x%lx but 0 GOT entries patched "
                 "(binary may be statically linked or use full RELRO)",
                 so_base);
    } else {
        res.status = INJECT_OK;
        snprintf(res.err_msg, sizeof(res.err_msg),
                 "Injected successfully. Library at 0x%lx, %d GOT entries patched",
                 so_base, patched);
    }

    return res;
}

#ifdef INJECTOR_STANDALONE
int main(int argc, char* argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <pid> <lib_path>\n", argv[0]);
        return 1;
    }
    pid_t pid = (pid_t)atoi(argv[1]);
    const char* lib = argv[2];

    printf("Injecting %s into PID %d...\n", lib, pid);
    inject_result_t r = inject_library(pid, lib);
    printf("Status: %d\n", r.status);
    printf("Message: %s\n", r.err_msg);
    printf("Patched: %d GOT entries\n", r.patched_count);
    return r.status == INJECT_OK ? 0 : 1;
}
#endif
