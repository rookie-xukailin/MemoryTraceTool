/*
 * 综合性 demo:模拟 flasher 类型的真实后端业务进程(RPC 多线程模型)
 *
 * 模拟场景:
 *   - 主线程接收"RPC 请求",投递任务到队列
 *   - 4 个 worker 线程从队列取任务执行
 *   - 任务链路:任务1 → fakebiz_normal.so → 业务回调
 *              任务2 → fakebiz_deep1.so → fakebiz_deep2.so(三层 .so 嵌套)
 *              任务3 → fakebiz_misuse.so(不规范用法)
 *   - 进程内直接泄漏(主线程 + worker 都产生)
 *   - 故意不 dlclose(模拟模块未卸载)
 *
 * 编译选项:-O2 -fomit-frame-pointer (模拟 release flasher)
 *
 * 关键覆盖点:
 *   - 多线程并发分配(stripe lock 真实竞争)
 *   - 跨线程 backtrace 断裂(RPC 模式天然特性)
 *   - 深栈嵌套(.so A → .so B → .so C + 业务回调)
 *   - thread-local backtrace buffer 一致性
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <pthread.h>

#define NUM_WORKERS 4
#define NUM_TASKS   16  /* 总任务数,会跨多个 .so */

typedef enum {
    TASK_BIZ_NORMAL = 0,
    TASK_BIZ_DEEP,
    TASK_BIZ_MISUSE_STRDUP,
    TASK_BIZ_MISUSE_ASPRINTF,
    TASK_BIZ_MISUSE_REALLOC,
    TASK_BIZ_MISUSE_CACHE,
    TASK_IN_PROCESS_LEAK,
    TASK_TYPE_COUNT
} task_type_t;

typedef struct {
    task_type_t type;
    int         task_id;
} task_t;

/* 简单的任务队列(互斥锁 + 条件变量) */
static task_t        g_task_queue[64];
static int           g_task_head = 0;
static int           g_task_tail = 0;
static pthread_mutex_t g_task_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_task_cond = PTHREAD_COND_INITIALIZER;
static int           g_shutdown = 0;        /* 1=主线程已投递完所有任务,worker 取空后退出 */

__attribute__((noinline)) static void leak_in_worker(int idx)
{
    /* worker 线程内的多层调用栈 + 泄漏 */
    void *p = malloc(48 + idx);
    if (p) {
        memset(p, 0xBB, 48 + idx);
        ((volatile char*)p)[0] = (char)idx;
    }
    /* 故意不释放 */
}

typedef void (*biz_func_t)(int);

static void call_biz(const char *so_path, const char *sym, int arg)
{
    void *handle = dlopen(so_path, RTLD_NOW);
    if (handle == NULL) return;
    biz_func_t fn = (biz_func_t)dlsym(handle, sym);
    if (fn == NULL) {
        dlclose(handle);
        return;
    }
    fn(arg);
    /* 故意:不 dlclose(handle) — 模拟模块未卸载 */
}

/* worker 线程主循环 */
static void *worker_main(void *arg)
{
    int worker_id = (int)(long)arg;
    (void)worker_id;

    for (;;) {
        task_t task;
        pthread_mutex_lock(&g_task_lock);
        /* 等待:队列空 + 未 shutdown 时阻塞 */
        while (g_task_head == g_task_tail && !g_shutdown)
            pthread_cond_wait(&g_task_cond, &g_task_lock);

        if (g_task_head == g_task_tail) {
            /* 队列空且 shutdown:退出 */
            pthread_mutex_unlock(&g_task_lock);
            break;
        }

        task = g_task_queue[g_task_head % 64];
        g_task_head++;
        pthread_mutex_unlock(&g_task_lock);

        /* 执行任务(模拟 RPC 回调) */
        switch (task.type) {
        case TASK_BIZ_NORMAL:
            call_biz("./fakebiz_normal.so", "biz_normal_call", 4);
            break;
        case TASK_BIZ_DEEP:
            call_biz("./fakebiz_deep1.so", "biz_deep1_handle", task.task_id);
            break;
        case TASK_BIZ_MISUSE_STRDUP:
            call_biz("./fakebiz_misuse.so", "biz_misuse_strdup", 5);
            break;
        case TASK_BIZ_MISUSE_ASPRINTF:
            call_biz("./fakebiz_misuse.so", "biz_misuse_asprintf", 5);
            break;
        case TASK_BIZ_MISUSE_REALLOC:
            call_biz("./fakebiz_misuse.so", "biz_misuse_realloc_bad", 3);
            break;
        case TASK_BIZ_MISUSE_CACHE:
            call_biz("./fakebiz_misuse.so", "biz_misuse_global_cache", 8);
            break;
        case TASK_IN_PROCESS_LEAK:
            leak_in_worker(task.task_id);
            break;
        default:
            break;
        }
    }

    return NULL;
}

/* 主线程投递任务 */
static void submit_task(task_type_t type, int task_id)
{
    pthread_mutex_lock(&g_task_lock);
    g_task_queue[g_task_tail % 64] = (task_t){type, task_id};
    g_task_tail++;
    pthread_cond_signal(&g_task_cond);
    pthread_mutex_unlock(&g_task_lock);
}

int main(void)
{
    printf("=== Realistic Demo (RPC multi-threaded) ===\n");
    printf("PID: %d, workers: %d, tasks: %d\n\n",
           (int)getpid(), NUM_WORKERS, NUM_TASKS);

    /* 启动 worker 线程池 */
    pthread_t workers[NUM_WORKERS];
    for (int i = 0; i < NUM_WORKERS; i++) {
        if (pthread_create(&workers[i], NULL, worker_main, (void*)(long)i) != 0) {
            fprintf(stderr, "Failed to create worker %d\n", i);
            return 1;
        }
    }

    /* 主线程投递任务,模拟 RPC 请求接入 */
    printf("--- Submitting %d RPC tasks ---\n", NUM_TASKS);
    for (int i = 0; i < NUM_TASKS; i++) {
        task_type_t type = (task_type_t)(i % TASK_TYPE_COUNT);
        submit_task(type, i);
    }

    /* 等所有任务完成 */
    pthread_mutex_lock(&g_task_lock);
    g_shutdown = 1;  /* 标记:不再有新任务 */
    pthread_cond_broadcast(&g_task_cond);
    pthread_mutex_unlock(&g_task_lock);

    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_join(workers[i], NULL);
    }

    printf("\nAll %d tasks done, workers exited.\n", NUM_TASKS);
    printf("Waiting 3s for hook + scan...\n");
    sleep(3);
    return 0;
}
