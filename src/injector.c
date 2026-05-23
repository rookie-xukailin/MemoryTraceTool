/*
 * MemoryTraceTool — ptrace 运行时库注入 + GOT 热修补。
 *
 * 将 libmemorytracetool.so 注入到正在运行的进程中：
 *   1. ptrace ATTACH 暂停目标进程
 *   2. 在目标进程中远程调用 __libc_dlopen_mode 加载我们的 .so
 *   3. 解析目标 ELF64 的 .rela.plt 找到 malloc/free/calloc/realloc 的 GOT 表项
 *   4. 将 GOT 表项改写为我们的钩子函数地址
 *   5. 恢复寄存器并 DETACH
 *
 * 仅支持 x86_64 Linux，依赖 ELF64 格式和 ptrace 系统调用。
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

/* 钩取的符号名列表 */
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

#define MAX_REGIONS 256

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
    return count;
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
            if (regions[i].path[0] && !strstr(regions[i].path, ".so"))
                return &regions[i];
        }
    }
    return NULL;
}

/* ---- 辅助: ELF64 符号解析 ---- */

/**
 * 从 ELF64 文件中查找指定符号的虚拟地址偏移。
 */
static int elf_find_symbol(const char* elf_path, const char* sym_name,
                           unsigned long* out_offset)
{
    FILE* f = fopen(elf_path, "rb");
    if (!f) return -1;

    Elf64_Ehdr ehdr;
    if (fread(&ehdr, 1, sizeof(ehdr), f) != sizeof(ehdr)) goto fail;
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) goto fail;
    if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) goto fail;

    Elf64_Shdr shstr_shdr;
    fseek(f, ehdr.e_shoff + (long)(ehdr.e_shstrndx * sizeof(Elf64_Shdr)), SEEK_SET);
    if (fread(&shstr_shdr, 1, sizeof(shstr_shdr), f) != sizeof(shstr_shdr)) goto fail;

    char* shstrtab = (char*)malloc(shstr_shdr.sh_size);
    if (!shstrtab) goto fail;
    fseek(f, shstr_shdr.sh_offset, SEEK_SET);
    if (fread(shstrtab, 1, shstr_shdr.sh_size, f) != shstr_shdr.sh_size) {
        free(shstrtab);
        goto fail;
    }

    Elf64_Shdr* shdrs = (Elf64_Shdr*)malloc(ehdr.e_shnum * sizeof(Elf64_Shdr));
    if (!shdrs) { free(shstrtab); goto fail; }
    fseek(f, ehdr.e_shoff, SEEK_SET);
    if (fread(shdrs, 1, ehdr.e_shnum * sizeof(Elf64_Shdr), f)
        != ehdr.e_shnum * sizeof(Elf64_Shdr)) {
        free(shdrs); free(shstrtab); goto fail;
    }

    Elf64_Shdr *symtab_shdr = NULL, *strtab_shdr = NULL, *dynsym_shdr = NULL, *dynstr_shdr = NULL;
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

    for (int table = 0; table < 2 && !found; table++) {
        Elf64_Shdr* sym_hdr = (table == 0) ? dynsym_shdr : symtab_shdr;
        Elf64_Shdr* str_hdr = (table == 0) ? dynstr_shdr : strtab_shdr;
        if (!sym_hdr || !str_hdr) continue;

        char* strtab_data = (char*)malloc(str_hdr->sh_size);
        if (!strtab_data) continue;
        fseek(f, str_hdr->sh_offset, SEEK_SET);
        if (fread(strtab_data, 1, str_hdr->sh_size, f) != str_hdr->sh_size) {
            free(strtab_data);
            continue;
        }

        int nsyms = (int)(sym_hdr->sh_size / sizeof(Elf64_Sym));
        Elf64_Sym* syms = (Elf64_Sym*)malloc(sym_hdr->sh_size);
        if (!syms) { free(strtab_data); continue; }
        fseek(f, sym_hdr->sh_offset, SEEK_SET);
        if (fread(syms, 1, sym_hdr->sh_size, f) != sym_hdr->sh_size) {
            free(syms); free(strtab_data); continue;
        }

        for (int i = 0; i < nsyms; i++) {
            const char* name = strtab_data + syms[i].st_name;
            if (strcmp(name, sym_name) == 0 && syms[i].st_value != 0) {
                *out_offset = syms[i].st_value;
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
 * 安全写入目标进程内存（8 字节对齐，每次 8 字节）。
 */
static int ptrace_write_mem(pid_t pid, unsigned long addr,
                            const void* data, size_t len)
{
    const unsigned long* words = (const unsigned long*)data;
    size_t nwords = (len + 7) / 8;

    for (size_t i = 0; i < nwords; i++) {
        unsigned long word = 0;
        size_t remain = len - i * 8;
        if (remain >= 8) {
            word = words[i];
        } else {
            long existing = ptrace(PTRACE_PEEKDATA, pid,
                                   (void*)(addr + i * 8), NULL);
            if (existing == -1 && errno != 0) return -1;
            memcpy(&word, &words[i], remain);
            size_t existing_off = remain;
            memcpy((char*)&word + existing_off,
                   (char*)&existing + existing_off, 8 - remain);
        }
        if (ptrace(PTRACE_POKEDATA, pid,
                   (void*)(addr + i * 8), (void*)word) == -1)
            return -1;
    }
    return 0;
}

/* ---- 远程函数调用 ---- */

/**
 * 在目标进程中远程调用 fn(arg1, arg2)。
 *
 * 通过操纵目标进程的寄存器和栈实现远程函数调用。
 * fn 执行 ret 后跳转到 trap_addr（含 INT3 断点），触发 SIGTRAP 后
 * 由 ptrace 捕获，从而取回返回值 rax。
 *
 * trap_addr 必须指向可执行内存（不可用栈，因为 NX 保护）。
 *
 * @param pid       目标 PID
 * @param fn_addr   目标函数地址
 * @param arg1      第一个参数 (rdi)
 * @param arg2      第二个参数 (rsi)
 * @param trap_addr 存放 INT3 的可执行内存地址（调用前后恢复原值）
 * @param regs      输入: 原始寄存器 / 输出: 调用后寄存器状态
 * @return          0 成功（rax 中含返回值），-1 失败
 */
static int ptrace_remote_call(pid_t pid, unsigned long fn_addr,
                              unsigned long arg1, unsigned long arg2,
                              unsigned long trap_addr,
                              struct user_regs_struct* regs)
{
    /* x86_64 ABI: 函数入口处 RSP 必须为 8 mod 16（模拟 call 压栈后的状态） */
    unsigned long orig_rsp = regs->rsp;
    /* 预留 16KB 栈空间供 dlopen 等复杂函数使用（256 字节不够） */
    unsigned long ret_slot = (orig_rsp - 16384) & ~0x0FUL;
    ret_slot -= 8;

    /* 保存原始数据以便恢复 */
    long old_ret = ptrace(PTRACE_PEEKDATA, pid, (void*)ret_slot, NULL);
    if (old_ret == -1 && errno != 0) return -1;
    long old_trap = ptrace(PTRACE_PEEKDATA, pid, (void*)trap_addr, NULL);
    if (old_trap == -1 && errno != 0) old_trap = 0;

    /* 在 trap_addr（可执行内存）写入 INT3 断点 */
    unsigned long trap_word = (unsigned long)old_trap;
    trap_word &= ~0xFFUL;
    trap_word |= 0xCC;
    if (ptrace(PTRACE_POKEDATA, pid, (void*)trap_addr, (void*)trap_word) == -1)
        return -1;

    /* 在栈上写入返回地址 = trap_addr（位于可执行内存，非 NX 栈） */
    if (ptrace(PTRACE_POKEDATA, pid, (void*)ret_slot,
               (void*)trap_addr) == -1) {
        ptrace(PTRACE_POKEDATA, pid, (void*)trap_addr, (void*)old_trap);
        return -1;
    }

    /* 构造调用寄存器: x86_64 calling convention */
    struct user_regs_struct call_regs = *regs;
    call_regs.orig_rax = (unsigned long)-1; /* 告知内核: 无 syscall 需重启 */
    call_regs.rip = fn_addr;
    call_regs.rdi = arg1;
    call_regs.rsi = arg2;
    call_regs.rdx = 0;
    call_regs.rcx = 0;
    call_regs.r8  = 0;
    call_regs.r9  = 0;
    call_regs.rsp = ret_slot;

    if (ptrace(PTRACE_SETREGS, pid, NULL, &call_regs) == -1) {
        ptrace(PTRACE_POKEDATA, pid, (void*)trap_addr, (void*)old_trap);
        ptrace(PTRACE_POKEDATA, pid, (void*)ret_slot, (void*)old_ret);
        return -1;
    }

    /* 执行目标进程直到遇到断点 */
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
        ptrace(PTRACE_POKEDATA, pid, (void*)trap_addr, (void*)old_trap);
        ptrace(PTRACE_POKEDATA, pid, (void*)ret_slot, (void*)old_ret);
        ptrace(PTRACE_SETREGS, pid, NULL, regs);
        return -1;
    }

    int status;
    if (waitpid(pid, &status, 0) == -1) {
        ptrace(PTRACE_POKEDATA, pid, (void*)trap_addr, (void*)old_trap);
        ptrace(PTRACE_POKEDATA, pid, (void*)ret_slot, (void*)old_ret);
        return -1;
    }

    /* debug: print what happened */
    fprintf(stderr, "[DEBUG] remote_call wait: status=0x%x", status);
    if (WIFEXITED(status)) fprintf(stderr, " EXITED(%d)", WEXITSTATUS(status));
    if (WIFSIGNALED(status)) fprintf(stderr, " SIGNALED(%s)", strsignal(WTERMSIG(status)));
    if (WIFSTOPPED(status)) fprintf(stderr, " STOPPED(%s)", strsignal(WSTOPSIG(status)));
    fprintf(stderr, "\n");

    /* 恢复栈和可执行内存上的原始数据 */
    ptrace(PTRACE_POKEDATA, pid, (void*)trap_addr, (void*)old_trap);
    ptrace(PTRACE_POKEDATA, pid, (void*)ret_slot, (void*)old_ret);

    /* 读取返回后的寄存器状态 */
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) == -1) return -1;

    fprintf(stderr, "[DEBUG] remote_call result: RIP=0x%llx RAX=0x%llx\n",
            (unsigned long long)regs->rip, (unsigned long long)regs->rax);

    /* 必须是 SIGTRAP 才算成功 */
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        fprintf(stderr, "[DEBUG] Remote call failed: status=0x%x, sig=%d\n",
                status, WIFSTOPPED(status) ? WSTOPSIG(status) : -1);
        return -1;
    }

    /* INT3 断点后 RIP 指向 INT3 之后一条指令，回退到 INT3 处 */
    regs->rip -= 1;

    return 0;
}

/* ---- GOT 修补 ---- */

/** 将动态段的虚拟地址转换为文件偏移（遍历 PT_LOAD 程序头） */
static long vaddr_to_file_off(const Elf64_Phdr* phdrs, int phnum,
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
 * 解析目标可执行文件 ELF64，找到 malloc/free/calloc/realloc 的
 * PLT 重定位表项，用钩子函数地址覆盖 GOT 槽位。
 */
static int patch_got_entries(pid_t pid, const char* exe_path,
                             unsigned long exe_base,
                             const unsigned long hook_addrs[4])
{
    FILE* f = fopen(exe_path, "rb");
    if (!f) return -1;

    Elf64_Ehdr ehdr;
    if (fread(&ehdr, 1, sizeof(ehdr), f) != sizeof(ehdr)) { fclose(f); return -1; }
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) { fclose(f); return -1; }
    if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) { fclose(f); return -1; }

    /* PIE (ET_DYN) 可执行文件: r_offset 是偏移量，需加基址。
     * 非 PIE (ET_EXEC): r_offset 已是绝对地址。 */
    int is_pie = (ehdr.e_type == ET_DYN);

    Elf64_Phdr* phdrs = (Elf64_Phdr*)malloc(ehdr.e_phnum * sizeof(Elf64_Phdr));
    if (!phdrs) { fclose(f); return -1; }
    fseek(f, ehdr.e_phoff, SEEK_SET);
    if (fread(phdrs, 1, ehdr.e_phnum * sizeof(Elf64_Phdr), f)
        != ehdr.e_phnum * sizeof(Elf64_Phdr)) {
        free(phdrs); fclose(f); return -1;
    }

    unsigned long dyn_filesz = 0;
    long dyn_file_off = -1;

    for (int i = 0; i < ehdr.e_phnum; i++) {
        if (phdrs[i].p_type == PT_DYNAMIC) {
            dyn_filesz = phdrs[i].p_filesz;
            dyn_file_off = phdrs[i].p_offset;
            break;
        }
    }
    if (dyn_file_off < 0) { free(phdrs); fclose(f); return -1; }

    int ndyns = (int)(dyn_filesz / sizeof(Elf64_Dyn));
    Elf64_Dyn* dyns = (Elf64_Dyn*)malloc(dyn_filesz);
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
        case DT_JMPREL:   jmprel   = dyns[i].d_un.d_val; break;
        case DT_PLTRELSZ: pltrelsz = dyns[i].d_un.d_val; break;
        case DT_SYMTAB:   symtab   = dyns[i].d_un.d_val; break;
        case DT_STRTAB:   strtab   = dyns[i].d_un.d_val; break;
        }
    }

    if (!jmprel || !pltrelsz || !symtab || !strtab) {
        free(dyns); free(phdrs); fclose(f); return -1;
    }

    long rela_off = vaddr_to_file_off(phdrs, ehdr.e_phnum, jmprel);
    if (rela_off < 0) { free(dyns); free(phdrs); fclose(f); return -1; }
    int nrelocs = (int)(pltrelsz / sizeof(Elf64_Rela));

    long sym_off = vaddr_to_file_off(phdrs, ehdr.e_phnum, symtab);
    if (sym_off < 0) { free(dyns); free(phdrs); fclose(f); return -1; }
    long str_off = vaddr_to_file_off(phdrs, ehdr.e_phnum, strtab);
    if (str_off < 0) { free(dyns); free(phdrs); fclose(f); return -1; }
    size_t sym_size = (size_t)(str_off - sym_off);

    fseek(f, 0, SEEK_END);
    long file_sz = ftell(f);
    size_t str_size = (size_t)(file_sz - str_off);
    if (str_size > 16 * 1024 * 1024) str_size = 16 * 1024 * 1024;

    char* strtab_data = (char*)malloc(str_size);
    if (!strtab_data) { free(dyns); free(phdrs); fclose(f); return -1; }
    fseek(f, str_off, SEEK_SET);
    if (fread(strtab_data, 1, str_size, f) != str_size) {
        free(strtab_data); free(dyns); free(phdrs); fclose(f); return -1;
    }

    Elf64_Sym* syms = (Elf64_Sym*)malloc(sym_size);
    if (!syms) { free(strtab_data); free(dyns); free(phdrs); fclose(f); return -1; }
    fseek(f, sym_off, SEEK_SET);
    if (fread(syms, 1, sym_size, f) != sym_size) {
        free(syms); free(strtab_data); free(dyns); free(phdrs); fclose(f); return -1;
    }

    int patched = 0;
    fseek(f, rela_off, SEEK_SET);
    fprintf(stderr, "[DEBUG] patch_got: PIE=%d exe_base=0x%lx nrelocs=%d jmprel=0x%lx\n",
            is_pie, exe_base, nrelocs, jmprel);

    for (int i = 0; i < nrelocs; i++) {
        Elf64_Rela rela;
        if (fread(&rela, 1, sizeof(rela), f) != sizeof(rela)) break;

        if (ELF64_R_TYPE(rela.r_info) != R_X86_64_JUMP_SLOT) continue;

        unsigned long sym_idx = ELF64_R_SYM(rela.r_info);
        if (sym_idx >= sym_size / sizeof(Elf64_Sym)) continue;

        const char* name = strtab_data + syms[sym_idx].st_name;
        if (i < 5) fprintf(stderr, "[DEBUG] PLT[%d]: sym_idx=%lu name=%s r_offset=0x%lx\n", i, sym_idx, name, rela.r_offset);

        int hook_idx = -1;
        for (int j = 0; j < 4; j++) {
            if (strcmp(name, g_inject_hook_names[j]) == 0) {
                hook_idx = j;
                break;
            }
        }
        fprintf(stderr, "[DEBUG] hook_idx=%d for %s\n", hook_idx, name);
        if (hook_idx < 0) continue;

        /* PIE 可执行文件: r_offset 是链接时偏移，需加基址 */
        unsigned long got_addr = is_pie ? (exe_base + rela.r_offset) : rela.r_offset;
        unsigned long hook_addr = hook_addrs[hook_idx];

        errno = 0;
        if (ptrace(PTRACE_POKEDATA, pid, (void*)got_addr,
                   (void*)hook_addr) != -1) {
            fprintf(stderr, "[DEBUG] POKEDATA %s: got=0x%lx hook=0x%lx OK\n",
                    name, got_addr, hook_addr);
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
 * 将 libmemorytracetool.so 注入到目标进程。
 *
 * 完整流程：验证 PID → ATTACH → 查 libc → 远程 dlopen →
 * 查钩子符号 → GOT 修补 → DETACH
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
                      "Permission denied. Run daemon as root or: "
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
    struct user_regs_struct saved_regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &saved_regs) == -1) {
        set_error(&res, INJECT_ERR_ATTACH,
                  "PTRACE_GETREGS failed: %s", strerror(errno));
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return res;
    }

    /* ---- Step 3: 查找目标 libc 基址和可执行区域 ---- */
    mem_region_t regions[MAX_REGIONS];
    int nregions = read_maps(pid, regions, MAX_REGIONS);
    if (nregions <= 0) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        set_error(&res, INJECT_ERR_ATTACH,
                  "Cannot read /proc/%d/maps", pid);
        return res;
    }

    const mem_region_t* libc_region = find_region(regions, nregions, "libc", 1);
    if (!libc_region) {
        libc_region = find_region(regions, nregions, "libc-", 1);
    }
    if (!libc_region) {
        for (int i = 0; i < nregions; i++) {
            if (strstr(regions[i].path, "libc") && strchr(regions[i].perms, 'x')) {
                libc_region = &regions[i];
                break;
            }
        }
    }
    if (!libc_region) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        set_error(&res, INJECT_ERR_DLOPEN,
                  "Cannot find libc in /proc/%d/maps", pid);
        return res;
    }

    unsigned long libc_base = libc_region->start;

    /* 在 libc 可执行区域末尾预留 16 字节作为 INT3 陷阱地址。
     * 必须使用可执行内存（非栈），因为 NX 栈保护禁止在栈上执行代码。 */
    unsigned long trap_addr = (libc_region->end - 16) & ~0x0FUL;
    fprintf(stderr, "[DEBUG] libc r-xp: 0x%lx-0x%lx trap_addr=0x%lx\n",
            libc_base, libc_region->end, trap_addr);

    /* 通过自身进程的 dlsym 计算 dlopen 偏移（比解析目标 libc ELF 更可靠） */
    void* our_dlopen = dlsym(RTLD_DEFAULT, "dlopen");
    if (!our_dlopen) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        set_error(&res, INJECT_ERR_DLOPEN, "Cannot find dlopen in own process");
        return res;
    }

    /* 找到自身 libc 基址以计算偏移 */
    unsigned long our_libc_base = 0;
    {
        mem_region_t self_regions[MAX_REGIONS];
        int nself = read_maps(getpid(), self_regions, MAX_REGIONS);
        for (int i = 0; i < nself; i++) {
            if (strstr(self_regions[i].path, "libc") && strchr(self_regions[i].perms, 'x')) {
                our_libc_base = self_regions[i].start;
                break;
            }
        }
    }
    unsigned long dlopen_offset = (unsigned long)our_dlopen - our_libc_base;
    unsigned long target_dlopen = libc_base + dlopen_offset;
    fprintf(stderr, "[DEBUG] our_libc=0x%lx dlopen_off=0x%lx target_dlopen=0x%lx\n",
            our_libc_base, dlopen_offset, target_dlopen);

    /* ---- Step 4: 在目标栈上分配空间写入库路径 ---- */
    /* 放在 ret_slot 下方 32KB 处，避免与远程调用的栈帧冲突 */
    unsigned long str_addr = saved_regs.rsp - 32768;
    str_addr &= ~0x0FUL;

    size_t path_len = strlen(abs_lib) + 1;
    if (ptrace_write_mem(pid, str_addr, abs_lib, path_len) == -1) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        set_error(&res, INJECT_ERR_DLOPEN,
                  "Cannot write library path to target memory");
        return res;
    }

    /* ---- Step 5: 远程调用 dlopen ---- */
    struct user_regs_struct call_regs = saved_regs;
    if (ptrace_remote_call(pid, target_dlopen, str_addr, RTLD_LAZY,
                           trap_addr, &call_regs) != 0) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        set_error(&res, INJECT_ERR_CRASH,
                  "Target process crashed or exited during dlopen call");
        return res;
    }

    unsigned long lib_handle = call_regs.rax;
    if (lib_handle == 0) {
        ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        set_error(&res, INJECT_ERR_DLOPEN,
                  "dlopen(%s) returned NULL in target. Check library deps.",
                  abs_lib);
        return res;
    }

    /* ---- Step 6: 找到注入库中钩子函数地址 ---- */
    nregions = read_maps(pid, regions, MAX_REGIONS);
    const mem_region_t* our_lib = NULL;
    for (int i = 0; i < nregions; i++) {
        if (strstr(regions[i].path, "libmemorytracetool")) {
            our_lib = &regions[i];
            if (strchr(regions[i].perms, 'x')) break;
        }
    }
    if (!our_lib) {
        ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        set_error(&res, INJECT_ERR_DLOPEN,
                  "Library loaded but not found in /proc/%d/maps", pid);
        return res;
    }
    unsigned long so_base = our_lib->start;
    res.lib_base = so_base;

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
        ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        set_error(&res, INJECT_ERR_GOT,
                  "Found only %d/4 hook symbols in injected library", hooks_found);
        return res;
    }

    /* ---- Step 7: GOT 修补 ---- */
    char exe_link[64];
    snprintf(exe_link, sizeof(exe_link), "/proc/%d/exe", pid);
    char exe_path[512];
    ssize_t exe_len = readlink(exe_link, exe_path, sizeof(exe_path) - 1);
    if (exe_len <= 0) {
        ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        set_error(&res, INJECT_ERR_GOT,
                  "Cannot readlink /proc/%d/exe", pid);
        return res;
    }
    exe_path[exe_len] = '\0';

    /* 查找主可执行文件基址（最低地址映射，即 ELF load base）。
     * 不筛选 'x' 权限 — PIE 可执行文件的 .rela.plt r_offset 是相对于
     * 第一个 PT_LOAD 段（r--p）的偏移，而非 r-xp 段。 */
    const mem_region_t* exe_region = find_region(regions, nregions, NULL, 0);
    if (!exe_region) {
        ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        set_error(&res, INJECT_ERR_GOT, "Cannot find main executable mapping");
        return res;
    }
    unsigned long exe_base = exe_region->start;
    fprintf(stderr, "[DEBUG] exe_region: start=0x%lx end=0x%lx path=%s\n", exe_region->start, exe_region->end, exe_region->path);

    int patched = patch_got_entries(pid, exe_path, exe_base, hook_addrs);
    res.patched_count = patched;

    /* ---- Step 8: 恢复并分离 ---- */
    ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs);

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
