/* rwProcMem_module.h - 进程内存读写模块头文件 */
#ifndef _RWPROCMEM_MODULE_H
#define _RWPROCMEM_MODULE_H

#include <linux/types.h>
#include <linux/input.h>

/* ==================== 常量定义 ==================== */
#define DRIVER_NAME "rwProcMem_module"
#define DEVICE_NAME "proc_mem"
#define CLASS_NAME "rwProcMem"
#define INPUT_NAME "Process Memory Read/Write Module"

/* 隐蔽通信机制 */
#define MAGIC_SIGNATURE 0x50524F43  /* "PROC" */
#define CMD_CHANNEL_NUM 5           /* 多个命令通道增加隐蔽性 */

/* 命令类型 */
#define CMD_READ_MEMORY      0xB1
#define CMD_WRITE_MEMORY     0xB2
#define CMD_SCAN_MEMORY      0xB3
#define CMD_FIND_PATTERN     0xB4
#define CMD_GET_PROC_INFO    0xB5
#define CMD_SET_PROTECTION   0xB6
#define CMD_GET_STATUS       0xB7
#define CMD_ACTIVATE         0xB8
#define CMD_DEACTIVATE       0xB9
#define CMD_HEARTBEAT        0xBA

/* 操作模式 */
#define MODE_READ_ONLY       0
#define MODE_READ_WRITE      1
#define MODE_SCAN_ONLY       2
#define MODE_SILENT          3     /* 静默模式，不记录日志 */

/* 内存访问权限 */
#define PERM_READ            0x01
#define PERM_WRITE           0x02
#define PERM_EXECUTE         0x04
#define PERM_SCAN            0x08

/* ==================== 数据结构定义 ==================== */

/* 内存操作请求结构 */
struct mem_operation {
    pid_t pid;                      /* 目标进程ID */
    unsigned long address;          /* 内存地址 */
    size_t size;                    /* 操作大小 */
    int permission;                 /* 访问权限 */
    unsigned char *buffer;          /* 数据缓冲区 */
    int result;                     /* 操作结果 */
    unsigned long timestamp;        /* 时间戳 */
};

/* 内存模式扫描结构 */
struct pattern_scan {
    pid_t pid;
    unsigned long start_addr;
    unsigned long end_addr;
    unsigned char *pattern;         /* 要搜索的模式 */
    size_t pattern_len;             /* 模式长度 */
    unsigned long *matches;         /* 匹配地址列表 */
    int max_matches;                /* 最大匹配数 */
    int match_count;                /* 实际匹配数 */
    int wildcard_enabled;           /* 是否支持通配符 */
};

/* 进程信息结构 */
struct proc_info {
    pid_t pid;
    char comm[TASK_COMM_LEN];       /* 进程名 */
    unsigned long start_time;       /* 启动时间 */
    unsigned long vm_size;          /* 虚拟内存大小 */
    unsigned long rss;              /* 驻留内存大小 */
    int thread_count;               /* 线程数 */
    uid_t uid;                      /* 用户ID */
    gid_t gid;                      /* 组ID */
    unsigned long permissions;      /* 进程权限 */
};

/* 模块配置结构 */
struct rwproc_config {
    /* 激活状态 */
    int activated;
    unsigned long activate_time;
    
    /* 访问控制 */
    int max_operation_size;         /* 最大单次操作大小 */
    int max_total_size;             /* 最大总操作大小 */
    int require_authentication;     /* 是否需要认证 */
    unsigned char auth_key[32];     /* 认证密钥 */
    
    /* 扫描配置 */
    struct {
        int enabled;
        int max_scan_size;          /* 最大扫描大小 */
        int pattern_cache_size;     /* 模式缓存大小 */
        int wildcard_support;       /* 是否支持通配符 */
        int concurrent_scans;       /* 并发扫描数 */
    } scan;
    
    /* 内存操作配置 */
    struct {
        int read_enabled;
        int write_enabled;
        int exec_enabled;
        int bypass_protection;      /* 是否绕过内存保护 */
        int use_direct_mapping;     /* 是否使用直接映射 */
        int cache_enabled;          /* 是否启用缓存 */
        size_t cache_size;          /* 缓存大小 */
    } memory;
    
    /* 隐蔽设置 */
    int current_mode;
    int stealth_level;
    int log_enabled;                /* 是否记录日志 */
    int heartbeat_interval;
    int obfuscation_enabled;        /* 是否启用混淆 */
    
    /* 统计信息 */
    unsigned long stats_reads;
    unsigned long stats_writes;
    unsigned long stats_scans;
    unsigned long stats_finds;
    unsigned long stats_blocks;     /* 阻止的操作数 */
    
    /* 操作队列 */
    struct mem_operation *op_queue;
    int queue_size;
    int queue_head;
    int queue_tail;
};

/* 设备结构 */
struct rwproc_device {
    struct input_dev *input_dev;
    struct cdev cdev;
    dev_t devno;
    struct class *class;
    struct device *device;
    
    struct rwproc_config config;
    struct mutex lock;
    spinlock_t config_lock;         /* 用于在 timer 回调中保护简短并发访问 */
    
    /* 工作线程和命令队列 */
    struct task_struct *worker_thread;
    wait_queue_head_t cmd_waitq;
    
    /* 多通道命令缓冲区（增加隐蔽性） */
    struct {
        unsigned char data[256];
        int len;
        int channel;
        unsigned int magic;
        unsigned short crc;
    } cmd_channels[CMD_CHANNEL_NUM];
    
    /* 定时器用于心跳和清理 */
    struct timer_list heartbeat_timer;
    
    /* 隐蔽标识 */
    unsigned char hidden_id[16];
    
    /* 缓存管理 */
    struct {
        unsigned long *address_cache;
        unsigned char *data_cache;
        int cache_size;
        int cache_head;
        int cache_tail;
        spinlock_t cache_lock;
    } cache;
};

/* ==================== 函数声明 ==================== */

/* 辅助函数 */
static inline int rwproc_clamp(int val, int min, int max);
static int fast_sqrt(int x);
static unsigned short simple_crc16(const unsigned char *data, int len);
static void generate_hidden_id(unsigned char *id, int len);

/* 内存操作函数 */
static int read_process_memory(pid_t pid, unsigned long addr, 
                               unsigned char *buffer, size_t size);
static int write_process_memory(pid_t pid, unsigned long addr,
                                const unsigned char *buffer, size_t size);
static int scan_memory_range(pid_t pid, unsigned long start, 
                             unsigned long end, struct pattern_scan *scan);
static int find_memory_pattern(pid_t pid, unsigned char *pattern,
                               size_t pattern_len, unsigned long *matches,
                               int max_matches);

/* 进程信息函数 */
static int get_process_info(pid_t pid, struct proc_info *info);
static int list_processes(pid_t *pids, int max_pids);

/* 保护操作函数 */
static int set_memory_protection(pid_t pid, unsigned long addr,
                                 size_t size, int protection);
static int remove_memory_protection(pid_t pid, unsigned long addr,
                                    size_t size);

/* 设备操作函数 */
static int rwproc_device_init(void);
static void rwproc_device_cleanup(void);
static ssize_t rwproc_read(struct file *filp, char __user *buf,
                           size_t count, loff_t *f_pos);
static ssize_t rwproc_write(struct file *filp, const char __user *buf,
                            size_t count, loff_t *f_pos);
static long rwproc_ioctl(struct file *filp, unsigned int cmd,
                         unsigned long arg);

/* 命令处理函数 */
static void process_command_channel(int channel);
static int validate_command(unsigned char *data, int len,
                            unsigned int magic, unsigned short crc);
static void send_response(int channel, unsigned char *data, int len);

/* 定时器函数 */
static void heartbeat_timer_callback(struct timer_list *t);
static void setup_heartbeat_timer(void);
static void cleanup_heartbeat_timer(void);

/* 工作队列函数 */
static int worker_thread_func(void *data);
static void wakeup_worker_thread(void);

/* 缓存管理函数 */
static void init_cache(void);
static void cleanup_cache(void);
static int cache_lookup(unsigned long addr, unsigned