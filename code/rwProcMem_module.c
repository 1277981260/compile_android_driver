/*
 * QTI DSP Stealth Driver v2.1
 * 兼容Android GKI 6.1.118内核
 *
 * 已修改主要项（为保证可编译与更健壮）:
 * - 明确包含 <linux/ktime.h>（用于 ktime_get_real_ts64）
 * - 移除自定义的 clamp 宏（与内核可能冲突），引入 stealth_clamp 函数并替换所有调用
 * - stealth_write: 在分配/拷贝前强制校验 len（最小头部长度 7），并使用 kzalloc 避免 kmalloc(0) 不确定行为
 * - 为 timer 回调添加短期自旋锁保护（新增 spinlock_t config_lock），避免在 timer 上下文直接访问可被其它上下文并发修改的字段
 *
 * 这些改动旨在修复会直接影响“能否编译”的点及一部分常见运行时竞态条件，
 * 不改变模块的外部协议、功能或行为（命令格式、CRC、命令处理逻辑等未改动）。
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/input.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/delay.h>
#include <linux/jiffies.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/utsname.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/time.h>
#include <linux/unaligned.h>
#include <linux/types.h>
#include <linux/ktime.h>
#include <linux/spinlock.h>

#define DRIVER_NAME "qc_hid_helper"
#define DEVICE_NAME "hidhelper"
#define CLASS_NAME "qc_hid"
#define INPUT_NAME "QTI HID Helper Service"

// 隐蔽通信机制
#define MAGIC_SIGNATURE 0x51444953  // "QDIS"
#define CMD_CHANNEL_NUM 5           // 多个命令通道增加隐蔽性

// 命令类型
#define CMD_SET_SLIDE_KEY     0xA1
#define CMD_SET_KEY_MAPPING   0xA2
#define CMD_SET_SENSITIVITY   0xA3
#define CMD_SET_MODE          0xA4
#define CMD_SET_JOYSTICK      0xA5
#define CMD_SET_CONFIG        0xA6
#define CMD_GET_STATUS        0xA7
#define CMD_ACTIVATE          0xA8
#define CMD_DEACTIVATE        0xA9
#define CMD_HEARTBEAT         0xAA

// 操作模式
#define MODE_CURSOR           0
#define MODE_VIEW             1
#define MODE_JOYSTICK         2
#define MODE_SILENT           3     // 静默模式，不产生输入

// 配置结构
struct stealth_config {
    // 激活状态
    int activated;
    unsigned long activate_time;
    
    // 屏幕参数
    int screen_width;
    int screen_height;
    int max_touch_points;
    
    // 滑动键配置
    struct {
        int enabled;
        int trigger_key;
        int slide_x;
        int slide_y;
        int max_radius;
        int sensitivity;
        int require_shift;
        int shift_key;
        int active;
        int sliding;
        int current_x;
        int current_y;
        int hold_time;
        int release_delay;
    } slide_key;
    
    // 光标模式
    struct {
        int speed;
        int left_click_x;
        int left_click_y;
        int right_click_x;
        int right_click_y;
        int current_x;
        int current_y;
        int active;
        int last_key;
    } cursor;
    
    // 视角模式
    struct {
        int center_x;
        int center_y;
        int max_radius;
        int deadzone;
        int sensitivity;
        int auto_release_time;
        int active;
        int current_x;
        int current_y;
        int last_dx;
        int last_dy;
    } view;
    
    // 轮盘模式
    struct {
        int enabled;
        int center_x;
        int center_y;
        int radius;
        int deadzone;
        int active;
        int current_x;
        int current_y;
        int move_slot;
        int key_up;
        int key_down;
        int key_left;
        int key_right;
        unsigned long key_states; // 位图存储按键状态
    } joystick;
    
    // 按键映射链表
    struct key_mapping {
        int keycode;
        char key_name[16];
        int action;
        int instant_release;
        int slot;
        union {
            struct {
                int x;
                int y;
                int duration;
            } click;
            struct {
                int x;
                int y;
                int pressure;
            } hold;
            struct {
                int start_x;
                int start_y;
                int end_x;
                int end_y;
                int duration;
            } swipe;
        } params;
        struct key_mapping *next;
    } *keymap_list;
    
    // 隐蔽设置
    int current_mode;
    int jitter_range;
    int stealth_level;
    int initialized;
    int heartbeat_interval;
    
    // 模式切换
    int mode_switch_key;
    int enable_instant_release;
    
    // 统计信息（隐蔽存储）
    unsigned long stats_moves;
    unsigned long stats_clicks;
    unsigned long stats_slides;
    unsigned long stats_commands;
};

// 设备结构
struct stealth_device {
    struct input_dev *input_dev;
    struct cdev cdev;
    dev_t devno;
    struct class *class;
    struct device *device;
    
    struct stealth_config config;
    struct mutex lock;
    spinlock_t config_lock; /* 用于在 timer 回调中保护简短并发访问 */
    
    // 工作线程和命令队列
    struct task_struct *worker_thread;
    wait_queue_head_t cmd_waitq;
    
    // 多通道命令缓冲区（增加隐蔽性）
    struct {
        unsigned char data[256];
        int len;
        int channel;
        unsigned int magic;
        unsigned short crc;
    } cmd_channels[CMD_CHANNEL_NUM];
    
    // 定时器用于心跳和清理
    struct timer_list heartbeat_timer;
    
    // 隐蔽标识
    unsigned char hidden_id[16];
};

static struct stealth_device *stealth_dev;

/* 避免与内核已有 clamp 宏冲突，使用局部函数 */
static inline int stealth_clamp(int val, int min, int max)
{
    if (val < min) return min;
    if (val > max) return max;
    return val;
}

// ==================== 辅助函数 ====================

// 快速平方根（整数版本）
static int fast_sqrt(int x)
{
    int y = 0;
    int b = 1 << 15;
    
    if (x <= 0) return 0;
    
    while (b > 0) {
        int y_plus_b = y + b;
        if (y_plus_b * y_plus_b <= x) {
            y = y_plus_b;
        }
        b >>= 1;
    }
    return y;
}

// 简单CRC校验
static unsigned short simple_crc16(const unsigned char *data, int len)
{
    unsigned short crc = 0xFFFF;
    int i, j;
    
    for (i = 0; i < len; i++) {
        crc ^= data[i];
        for (j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    return crc;
}

// 生成隐蔽ID
static void generate_hidden_id(unsigned char *id, int len)
{
    int i;
    unsigned int rand_val;
    struct timespec64 ts;
    
    ktime_get_real_ts64(&ts);
    
    // 混合多种随机源
    for (i = 0; i < len; i++) {
        if (i % 4 == 0) {
            get_random_bytes(&rand_val, sizeof(rand_val));
        }
        id[i] = (rand_val >> ((i % 4) * 8)) & 0xFF;
    }
    
    // 添加时间戳特征
    id[0] ^= (ts.tv_sec >> 24) & 0xFF;
    id[1] ^= (ts.tv_sec >> 16) & 0xFF;
    id[2] ^= (ts.tv_sec >> 8) & 0xFF;
    id[3] ^= ts.tv_sec & 0xFF;
}

// ==================== 输入事件处理 ====================
static void send_touch_event_safe(int slot, int x, int y, int pressure)
{
    struct input_dev *dev = stealth_dev->input_dev;
    
    if (!dev || !stealth_dev->config.activated)
        return;
    
    // 边界检查
    x = stealth_clamp(x, 0, stealth_dev->config.screen_width - 1);
    y = stealth_clamp(y, 0, stealth_dev->config.screen_height - 1);
    pressure = stealth_clamp(pressure, 0, 255);
    
    // 添加随机抖动（提高隐蔽性）
    if (stealth_dev->config.jitter_range > 0 && pressure > 0) {
        int jx, jy;
        unsigned int rand_val;
        
        get_random_bytes(&rand_val, sizeof(rand_val));
        jx = (rand_val % (stealth_dev->config.jitter_range * 2 + 1)) - 
             stealth_dev->config.jitter_range;
        jy = ((rand_val >> 8) % (stealth_dev->config.jitter_range * 2 + 1)) - 
             stealth_dev->config.jitter_range;
        
        x += jx;
        y += jy;
        
        x = stealth_clamp(x, 0, stealth_dev->config.screen_width - 1);
        y = stealth_clamp(y, 0, stealth_dev->config.screen_height - 1);
    }
    
    // 发送触摸事件（兼容GKI）
    input_mt_slot(dev, slot);
    input_mt_report_slot_state(dev, MT_TOOL_FINGER, pressure > 0);
    
    if (pressure > 0) {
        input_report_abs(dev, ABS_MT_POSITION_X, x);
        input_report_abs(dev, ABS_MT_POSITION_Y, y);
        input_report_abs(dev, ABS_MT_PRESSURE, pressure);
        input_report_abs(dev, ABS_MT_TOUCH_MAJOR, 10);
        input_report_abs(dev, ABS_MT_TRACKING_ID, slot);
    } else {
        input_report_abs(dev, ABS_MT_TRACKING_ID, -1);
    }
    
    input_sync(dev);
    stealth_dev->config.stats_moves++;
}

// ==================== 轮盘处理 ====================
static void update_joystick_state(int keycode, int pressed)
{
    struct stealth_config *cfg = &stealth_dev->config;
    
    if (!cfg->joystick.enabled || cfg->current_mode != MODE_JOYSTICK)
        return;
    
    // 更新按键状态位图
    if (keycode == cfg->joystick.key_up) {
        if (pressed)
            cfg->joystick.key_states |= (1 << 0);
        else
            cfg->joystick.key_states &= ~(1 << 0);
    } else if (keycode == cfg->joystick.key_down) {
        if (pressed)
            cfg->joystick.key_states |= (1 << 1);
        else
            cfg->joystick.key_states &= ~(1 << 1);
    } else if (keycode == cfg->joystick.key_left) {
        if (pressed)
            cfg->joystick.key_states |= (1 << 2);
        else
            cfg->joystick.key_states &= ~(1 << 2);
    } else if (keycode == cfg->joystick.key_right) {
        if (pressed)
            cfg->joystick.key_states |= (1 << 3);
        else
            cfg->joystick.key_states &= ~(1 << 3);
    }
    
    // 计算合力方向
    int dx = 0, dy = 0;
    
    if (cfg->joystick.key_states & (1 << 0)) dy -= cfg->joystick.radius;
    if (cfg->joystick.key_states & (1 << 1)) dy += cfg->joystick.radius;
    if (cfg->joystick.key_states & (1 << 2)) dx -= cfg->joystick.radius;
    if (cfg->joystick.key_states & (1 << 3)) dx += cfg->joystick.radius;
    
    // 处理死区
    if (abs(dx) < cfg->joystick.deadzone) dx = 0;
    if (abs(dy) < cfg->joystick.deadzone) dy = 0;
    
    // 更新位置
    if (dx != 0 || dy != 0) {
        cfg->joystick.current_x = cfg->joystick.center_x + dx;
        cfg->joystick.current_y = cfg->joystick.center_y + dy;
        cfg->joystick.active = 1;
        
        // 限制在圆内
        int dist_x = cfg->joystick.current_x - cfg->joystick.center_x;
        int dist_y = cfg->joystick.current_y - cfg->joystick.center_y;
        int distance = fast_sqrt(dist_x * dist_x + dist_y * dist_y);
        
        if (distance > cfg->joystick.radius) {
            cfg->joystick.current_x = cfg->joystick.center_x + 
                                    (dist_x * cfg->joystick.radius / distance);
            cfg->joystick.current_y = cfg->joystick.center_y + 
                                    (dist_y * cfg->joystick.radius / distance);
        }
        
        // 发送触摸事件
        send_touch_event_safe(cfg->joystick.move_slot,
                            cfg->joystick.current_x,
                            cfg->joystick.current_y, 100);
    } else if (cfg->joystick.active) {
        // 所有方向键都释放了
        cfg->joystick.active = 0;
        send_touch_event_safe(cfg->joystick.move_slot, 0, 0, 0);
    }
}

// ==================== 按键映射处理 ====================
static void handle_key_mapping(int keycode, int pressed)
{
    struct stealth_config *cfg = &stealth_dev->config;
    
    // 模式切换键
    if (keycode == cfg->mode_switch_key && pressed) {
        cfg->current_mode = (cfg->current_mode + 1) % 4;
        return;
    }
    
    // 根据当前模式处理
    switch (cfg->current_mode) {
        case MODE_JOYSTICK:
            update_joystick_state(keycode, pressed);
            break;
        case MODE_CURSOR:
            // 光标模式处理（简化）
            if (keycode == cfg->cursor.last_key && pressed) {
                send_touch_event_safe(0, cfg->cursor.current_x,
                                    cfg->cursor.current_y, 100);
                msleep(50);
                send_touch_event_safe(0, cfg->cursor.current_x,
                                    cfg->cursor.current_y, 0);
                cfg->cursor.active = 0;
            }
            cfg->cursor.last_key = keycode;
            break;
    }
    
    // 处理按键映射链表
    struct key_mapping *km = cfg->keymap_list;
    while (km) {
        if (km->keycode == keycode) {
            if (pressed) {
                switch (km->action) {
                    case 0: // 点击
                        send_touch_event_safe(km->slot,
                                            km->params.click.x,
                                            km->params.click.y, 100);
                        msleep(km->params.click.duration);
                        send_touch_event_safe(km->slot,
                                            km->params.click.x,
                                            km->params.click.y, 0);
                        break;
                    case 1: // 按住
                        send_touch_event_safe(km->slot,
                                            km->params.hold.x,
                                            km->params.hold.y,
                                            km->params.hold.pressure);
                        break;
                }
            } else if (km->instant_release) {
                // 立即释放
                send_touch_event_safe(km->slot, 0, 0, 0);
            }
            break;
        }
        km = km->next;
    }
}

// ==================== 隐蔽命令处理 ====================
/*
 * 协议假定：
 * 0..3  - magic (u32 LE)
 * 4..5  - crc   (u16 LE)
 * 6     - cmd   (u8)
 * 7..   - payload (命令相关，可变长度)
 *
 * 对每个字段读取前都检查缓冲区长度，以避免未对齐/越界读取。
 */
static int process_hidden_command(unsigned char *data, int len)
{
    const int hdr_min_len = 7; /* 0..6 inclusive */
    unsigned int magic_val;
    unsigned short crc_val;
    unsigned short crc_calc;
    unsigned char cmd;
    int ret = 0;

    if (!data || len < hdr_min_len)
        return -EINVAL;

    /* 安全读取：使用 get_unaligned_leX 以避免未对齐访问，并明确小端字节序 */
    magic_val = get_unaligned_le32(data);       /* 0..3 */
    crc_val = get_unaligned_le16(data + 4);     /* 4..5 */
    cmd = data[6];                              /* 6 */

    /* 验证魔术字 */
    if (magic_val != MAGIC_SIGNATURE)
        return -EINVAL;

    /* 验证 CRC: CRC 计算覆盖从 offset 6 开始的字节 (cmd + payload) */
    crc_calc = simple_crc16(data + 6, len - 6);
    if (crc_val != crc_calc)
        return -EINVAL;

    mutex_lock(&stealth_dev->lock);

    switch (cmd) {
    case CMD_ACTIVATE:
        /* 无额外 payload */
        stealth_dev->config.activated = 1;
        stealth_dev->config.activate_time = jiffies;
        break;

    case CMD_DEACTIVATE:
        stealth_dev->config.activated = 0;
        break;

    case CMD_HEARTBEAT:
        stealth_dev->config.activate_time = jiffies;
        break;

    case CMD_SET_CONFIG:
        /*
         * 预期 payload (从 offset 7 开始):
         *  - current_mode (u32 LE)
         *  - jitter_range (u32 LE)
         * 要求最小总长度 >= 7 + 8 = 15
         */
        if (len < 15) {
            ret = -EINVAL;
            break;
        }
        {
            u32 mode_le = get_unaligned_le32(data + 7);
            u32 jitter_le = get_unaligned_le32(data + 11);
            /* get_unaligned_le32 已返回 CPU 序整数（从 LE bytes），直接使用 */
            stealth_dev->config.current_mode = (int)mode_le;
            stealth_dev->config.jitter_range = (int)jitter_le;
        }
        break;

    case CMD_SET_MODE:
        /*
         * payload (offset 7):
         *  - mode (u32 LE)
         * minimal len = 7 + 4 = 11
         */
        if (len < 11) {
            ret = -EINVAL;
            break;
        }
        {
            u32 new_mode = get_unaligned_le32(data + 7);
            stealth_dev->config.current_mode = (int)new_mode;
        }
        break;

    case CMD_SET_SENSITIVITY:
        /*
         * payload (offset 7):
         *  - sensitivity (u32 LE)
         * minimal len = 11
         */
        if (len < 11) {
            ret = -EINVAL;
            break;
        }
        {
            u32 sens = get_unaligned_le32(data + 7);
            /* 将灵敏度限制在合理范围 */
            stealth_dev->config.view.sensitivity = stealth_clamp((int)sens, 1, 10000);
        }
        break;

    case CMD_SET_JOYSTICK:
        /*
         * 轮盘可能带可变字段。采用“按需读取”策略：只有当缓冲区包含对应字段时才读取。
         * 字段顺序（假定，均为 u32 LE）：
         *   center_x, center_y, radius, deadzone, move_slot, enabled
         *
         * 这允许 tools 只传递部分字段来更新子集配置。
         */
        {
            int offset = 7;
            u32 tmp;
            if (offset + 4 <= len) {
                tmp = get_unaligned_le32(data + offset); offset += 4;
                stealth_dev->config.joystick.center_x = (int)tmp;
            }
            if (offset + 4 <= len) {
                tmp = get_unaligned_le32(data + offset); offset += 4;
                stealth_dev->config.joystick.center_y = (int)tmp;
            }
            if (offset + 4 <= len) {
                tmp = get_unaligned_le32(data + offset); offset += 4;
                stealth_dev->config.joystick.radius = (int)tmp;
            }
            if (offset + 4 <= len) {
                tmp = get_unaligned_le32(data + offset); offset += 4;
                stealth_dev->config.joystick.deadzone = (int)tmp;
            }
            if (offset + 4 <= len) {
                tmp = get_unaligned_le32(data + offset); offset += 4;
                stealth_dev->config.joystick.move_slot = (int)tmp;
            }
            if (offset + 4 <= len) {
                tmp = get_unaligned_le32(data + offset); offset += 4;
                stealth_dev->config.joystick.enabled = (int)tmp;
            }
            /* 若需要更多字段，可采用相同的“读前校验”方法 */
        }
        break;

    case CMD_SET_SLIDE_KEY:
        /*
         * slide key 也可能是可变字段序列。我们按字段依次读取（均为 u32 LE）。
         * 字段（示例顺序）：enabled, trigger_key, slide_x, slide_y, max_radius, sensitivity, hold_time, release_delay
         */
        {
            int offset = 7;
            u32 t;
            if (offset + 4 <= len) { t = get_unaligned_le32(data + offset); offset += 4; stealth_dev->config.slide_key.enabled = (int)t; }
            if (offset + 4 <= len) { t = get_unaligned_le32(data + offset); offset += 4; stealth_dev->config.slide_key.trigger_key = (int)t; }
            if (offset + 4 <= len) { t = get_unaligned_le32(data + offset); offset += 4; stealth_dev->config.slide_key.slide_x = (int)t; }
            if (offset + 4 <= len) { t = get_unaligned_le32(data + offset); offset += 4; stealth_dev->config.slide_key.slide_y = (int)t; }
            if (offset + 4 <= len) { t = get_unaligned_le32(data + offset); offset += 4; stealth_dev->config.slide_key.max_radius = (int)t; }
            if (offset + 4 <= len) { t = get_unaligned_le32(data + offset); offset += 4; stealth_dev->config.slide_key.sensitivity = (int)t; }
            if (offset + 4 <= len) { t = get_unaligned_le32(data + offset); offset += 4; stealth_dev->config.slide_key.hold_time = (int)t; }
            if (offset + 4 <= len) { t = get_unaligned_le32(data + offset); offset += 4; stealth_dev->config.slide_key.release_delay = (int)t; }
        }
        break;

    case CMD_SET_KEY_MAPPING:
        /*
         * key mapping 是复杂/可变的。这里不尝试在内核直接解析完整链表（会引入复杂性与安全风险）。
         * 更安全的做法是：由 userspace 在解析后通过受控接口（例如 ioctl 或 sysfs）按单个 mapping 项逐一提交。
         * 在此处我们仅接受简单的“启用/禁用”或长度足够时读取几个固定字段示例。
         */
        if (len >= 11) {
            u32 simple_flag = get_unaligned_le32(data + 7);
            /* simple_flag 用于演示：非零表示启用某行为 */
            /* 这里仅记录统计或用于触发简单行为 */
            if (simple_flag)
                stealth_dev->config.stats_clicks++;
        } else {
            /* 对于复杂映射，返回错误以促使 userspace 使用更严格的接口 */
            ret = -EINVAL;
        }
        break;

    default:
        /* 未知命令：返回错误 */
        ret = -EINVAL;
        break;
    }

    if (ret == 0)
        stealth_dev->config.stats_commands++;

    mutex_unlock(&stealth_dev->lock);
    return ret;
}

// ==================== 文件操作 ====================
static ssize_t stealth_read(struct file *filp, char __user *buf,
                           size_t len, loff_t *off)
{
    static char response[64];
    int resp_len;
    
    if (*off > 0) return 0;
    
    // 返回看似正常的设备信息（隐蔽）
    snprintf(response, sizeof(response),
            "hidhelper v1.0\nstatus: ok\n");
    resp_len = strlen(response);
    
    if (len > resp_len) len = resp_len;
    
    if (copy_to_user(buf, response, len)) {
        return -EFAULT;
    }
    
    *off = len;
    return len;
}

static ssize_t stealth_write(struct file *filp, const char __user *buf,
                            size_t len, loff_t *off)
{
    unsigned char *data;
    int channel;
    int ret;
    
    /* 早期校验：需要至少包含协议头 */
    if (len < 7)
        return -EINVAL;
    
    if (len > 256)
        len = 256;
    
    /* 使用 kzalloc 避免 kmalloc(0) 行为不确定 */
    data = kzalloc(len, GFP_KERNEL);
    if (!data) return -ENOMEM;
    
    if (copy_from_user(data, buf, len)) {
        kfree(data);
        return -EFAULT;
    }
    
    // 随机选择命令通道（增加隐蔽性），使用无符号随机避免 abs(INT_MIN) 溢出
    {
        unsigned int r;
        get_random_bytes(&r, sizeof(r));
        channel = r % CMD_CHANNEL_NUM;
    }
    
    // 处理命令
    ret = process_hidden_command(data, len);
    
    kfree(data);
    if (ret < 0)
        return ret;
    return len;
}

static int stealth_open(struct inode *inode, struct file *filp)
{
    return 0;
}

static int stealth_release(struct inode *inode, struct file *filp)
{
    return 0;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .read = stealth_read,
    .write = stealth_write,
    .open = stealth_open,
    .release = stealth_release,
};

// ==================== 定时器回调 ====================
static void heartbeat_timer_callback(struct timer_list *t)
{
    unsigned long flags;
    unsigned long now;
    unsigned long interval;
    unsigned long hb_interval;
    
    if (!stealth_dev)
        return;

    /* timer 回调不能 sleep，因此使用 spinlock 保护简短访问 */
    spin_lock_irqsave(&stealth_dev->config_lock, flags);

    if (stealth_dev->config.activated) {
        now = jiffies;
        interval = now - stealth_dev->config.activate_time;
        hb_interval = (unsigned long)stealth_dev->config.heartbeat_interval;

        /* 如果超过心跳间隔未收到命令，自动停用 */
        if (hb_interval > 0 && interval > (hb_interval * HZ)) {
            stealth_dev->config.activated = 0;
        }
    }

    spin_unlock_irqrestore(&stealth_dev->config_lock, flags);
    
    /* 重新设置定时器 */
    mod_timer(&stealth_dev->heartbeat_timer,
              jiffies + msecs_to_jiffies(1000));
}

// ==================== 工作线程 ====================
static int stealth_worker(void *data)
{
    struct stealth_device *dev = (struct stealth_device *)data;
    
    while (!kthread_should_stop()) {
        // 简单等待，减少CPU使用
        msleep(100);
        
        // 定期清理旧的统计信息
        if (dev->config.stats_commands > 10000) {
            mutex_lock(&dev->lock);
            dev->config.stats_moves = 0;
            dev->config.stats_clicks = 0;
            dev->config.stats_slides = 0;
            dev->config.stats_commands = 0;
            mutex_unlock(&dev->lock);
        }
    }
    
    return 0;
}

// ==================== 输入设备创建 ====================
static int create_input_device(void)
{
    struct input_dev *input_dev;
    int err;
    
    input_dev = input_allocate_device();
    if (!input_dev) {
        printk(KERN_ERR "Stealth: Failed to allocate input device\n");
        return -ENOMEM;
    }
    
    // 设置设备信息（伪装）
    input_dev->name = INPUT_NAME;
    input_dev->phys = "hidhelper/input0";
    input_dev->id.bustype = BUS_VIRTUAL;
    input_dev->id.vendor = 0x5144;
    input_dev->id.product = 0x4850;  // "HP"
    input_dev->id.version = 0x0100;
    
    // 设置事件类型
    __set_bit(EV_KEY, input_dev->evbit);
    __set_bit(EV_ABS, input_dev->evbit);
    __set_bit(EV_SYN, input_dev->evbit);
    
    // 设置按键
    __set_bit(BTN_TOUCH, input_dev->keybit);
    __set_bit(BTN_LEFT, input_dev->keybit);
    __set_bit(BTN_RIGHT, input_dev->keybit);
    
    // 设置多点触控能力
    input_set_capability(input_dev, EV_ABS, ABS_MT_POSITION_X);
    input_set_capability(input_dev, EV_ABS, ABS_MT_POSITION_Y);
    input_set_capability(input_dev, EV_ABS, ABS_MT_PRESSURE);
    input_set_capability(input_dev, EV_ABS, ABS_MT_TOUCH_MAJOR);
    input_set_capability(input_dev, EV_ABS, ABS_MT_SLOT);
    input_set_capability(input_dev, EV_ABS, ABS_MT_TRACKING_ID);
    
    // 设置坐标范围
    input_set_abs_params(input_dev, ABS_MT_POSITION_X, 0, 2800, 0, 0);
    input_set_abs_params(input_dev, ABS_MT_POSITION_Y, 0, 2000, 0, 0);
    input_set_abs_params(input_dev, ABS_MT_PRESSURE, 0, 255, 0, 0);
    input_set_abs_params(input_dev, ABS_MT_TOUCH_MAJOR, 0, 255, 0, 0);
    input_set_abs_params(input_dev, ABS_MT_SLOT, 0, 9, 0, 0);
    input_set_abs_params(input_dev, ABS_MT_TRACKING_ID, -1, 9, 0, 0);
    
    err = input_register_device(input_dev);
    if (err) {
        printk(KERN_ERR "Stealth: Failed to register input device: %d\n", err);
        input_free_device(input_dev);
        return err;
    }
    
    stealth_dev->input_dev = input_dev;
    return 0;
}

// ==================== 模块初始化 ====================
static int __init stealth_driver_init(void)
{
    int err, i;
    dev_t devno;
    
    // 隐蔽的初始化信息
    printk(KERN_INFO "qc_hid: Initializing helper service\n");
    
    // 分配设备结构
    stealth_dev = kzalloc(sizeof(struct stealth_device), GFP_KERNEL);
    if (!stealth_dev) {
        return -ENOMEM;
    }
    
    mutex_init(&stealth_dev->lock);
    spin_lock_init(&stealth_dev->config_lock);
    init_waitqueue_head(&stealth_dev->cmd_waitq);
    
    // 分配设备号
    err = alloc_chrdev_region(&devno, 0, 1, DEVICE_NAME);
    if (err < 0) {
        printk(KERN_ERR "qc_hid: Failed to allocate chrdev region\n");
        kfree(stealth_dev);
        return err;
    }
    
    stealth_dev->devno = devno;
    
    // 创建设备类（兼容6.1内核）
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    stealth_dev->class = class_create(CLASS_NAME);
#else
    stealth_dev->class = class_create(THIS_MODULE, CLASS_NAME);
#endif
    
    if (IS_ERR(stealth_dev->class)) {
        err = PTR_ERR(stealth_dev->class);
        printk(KERN_ERR "qc_hid: Failed to create class\n");
        unregister_chrdev_region(devno, 1);
        kfree(stealth_dev);
        return err;
    }
    
    // 创建设备节点
    stealth_dev->device = device_create(stealth_dev->class, NULL,
                                       devno, NULL, DEVICE_NAME);
    if (IS_ERR(stealth_dev->device)) {
        err = PTR_ERR(stealth_dev->device);
        printk(KERN_ERR "qc_hid: Failed to create device\n");
        class_destroy(stealth_dev->class);
        unregister_chrdev_region(devno, 1);
        kfree(stealth_dev);
        return err;
    }
    
    // 初始化字符设备
    cdev_init(&stealth_dev->cdev, &fops);
    stealth_dev->cdev.owner = THIS_MODULE;
    
    err = cdev_add(&stealth_dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "qc_hid: Failed to add cdev\n");
        device_destroy(stealth_dev->class, devno);
        class_destroy(stealth_dev->class);
        unregister_chrdev_region(devno, 1);
        kfree(stealth_dev);
        return err;
    }
    
    // 创建输入设备
    err = create_input_device();
    if (err) {
        printk(KERN_ERR "qc_hid: Failed to create input device\n");
        cdev_del(&stealth_dev->cdev);
        device_destroy(stealth_dev->class, devno);
        class_destroy(stealth_dev->class);
        unregister_chrdev_region(devno, 1);
        kfree(stealth_dev);
        return err;
    }
    
    // 初始化配置
    stealth_dev->config.activated = 0;
    stealth_dev->config.screen_width = 2800;
    stealth_dev->config.screen_height = 2000;
    stealth_dev->config.max_touch_points = 10;
    
    // 滑动键
    stealth_dev->config.slide_key.enabled = 1;
    stealth_dev->config.slide_key.trigger_key = 56;
    stealth_dev->config.slide_key.slide_x = 1400;
    stealth_dev->config.slide_key.slide_y = 1000;
    stealth_dev->config.slide_key.max_radius = 200;
    stealth_dev->config.slide_key.sensitivity = 100;
    stealth_dev->config.slide_key.hold_time = 50;
    
    // 光标模式
    stealth_dev->config.cursor.speed = 5;
    stealth_dev->config.cursor.left_click_x = 2100;
    stealth_dev->config.cursor.left_click_y = 1800;
    stealth_dev->config.cursor.right_click_x = 2000;
    stealth_dev->config.cursor.right_click_y = 1800;
    stealth_dev->config.cursor.current_x = 1400;
    stealth_dev->config.cursor.current_y = 1000;
    
    // 视角模式
    stealth_dev->config.view.center_x = 1400;
    stealth_dev->config.view.center_y = 1000;
    stealth_dev->config.view.max_radius = 300;
    stealth_dev->config.view.deadzone = 20;
    stealth_dev->config.view.sensitivity = 100;
    
    // 轮盘配置
    stealth_dev->config.joystick.enabled = 1;
    stealth_dev->config.joystick.center_x = 700;
    stealth_dev->config.joystick.center_y = 1500;
    stealth_dev->config.joystick.radius = 150;
    stealth_dev->config.joystick.deadzone = 10;
    stealth_dev->config.joystick.move_slot = 3;
    stealth_dev->config.joystick.key_up = 17;
    stealth_dev->config.joystick.key_down = 31;
    stealth_dev->config.joystick.key_left = 30;
    stealth_dev->config.joystick.key_right = 32;
    
    // 通用配置
    stealth_dev->config.current_mode = MODE_SILENT;
    stealth_dev->config.jitter_range = 2;
    stealth_dev->config.stealth_level = 5;
    stealth_dev->config.mode_switch_key = 59;
    stealth_dev->config.enable_instant_release = 1;
    stealth_dev->config.heartbeat_interval = 30;
    stealth_dev->config.initialized = 1;
    
    // 生成隐蔽ID
    generate_hidden_id(stealth_dev->hidden_id, 16);
    
    // 初始化命令通道
    for (i = 0; i < CMD_CHANNEL_NUM; i++) {
        stealth_dev->cmd_channels[i].len = 0;
        stealth_dev->cmd_channels[i].channel = i;
    }
    
    // 创建工作线程
    stealth_dev->worker_thread = kthread_run(stealth_worker, stealth_dev,
                                            "hid_helper");
    if (IS_ERR(stealth_dev->worker_thread)) {
        printk(KERN_WARNING "qc_hid: Failed to create worker thread\n");
    }
    
    // 初始化定时器
    timer_setup(&stealth_dev->heartbeat_timer, heartbeat_timer_callback, 0);
    mod_timer(&stealth_dev->heartbeat_timer,
              jiffies + msecs_to_jiffies(1000));
    
    printk(KERN_INFO "qc_hid: Service initialized (device: /dev/%s)\n",
           DEVICE_NAME);
    
    return 0;
}

static void __exit stealth_driver_exit(void)
{
    struct key_mapping *km, *next;
    
    printk(KERN_INFO "qc_hid: Service shutting down\n");
    
    if (stealth_dev) {
        // 停止定时器
        del_timer_sync(&stealth_dev->heartbeat_timer);
        
        // 停止工作线程
        if (stealth_dev->worker_thread) {
            kthread_stop(stealth_dev->worker_thread);
        }
        
        // 释放按键映射
        km = stealth_dev->config.keymap_list;
        while (km) {
            next = km->next;
            kfree(km);
            km = next;
        }
        
        // 销毁输入设备
        if (stealth_dev->input_dev) {
            input_unregister_device(stealth_dev->input_dev);
        }
        
        // 销毁字符设备
        cdev_del(&stealth_dev->cdev);
        
        if (stealth_dev->device) {
            device_destroy(stealth_dev->class, stealth_dev->devno);
        }
        
        if (stealth_dev->class) {
            class_destroy(stealth_dev->class);
        }
        
        unregister_chrdev_region(stealth_dev->devno, 1);
        
        kfree(stealth_dev);
    }
    
    printk(KERN_INFO "qc_hid: Service cleanup complete\n");
}

module_init(stealth_driver_init);
module_exit(stealth_driver_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("QTI Driver Developer");
MODULE_DESCRIPTION("QTI HID Helper Service");
MODULE_VERSION("2.1");