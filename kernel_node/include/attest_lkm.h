#ifndef ATTEST_LKM_H
#define ATTEST_LKM_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/string.h>

#define ATTEST_VERSION_MAJOR 1
#define ATTEST_VERSION_MINOR 0
#define ATTEST_VERSION_PATCH 0

#define NETLINK_ATTEST 31

#define MSG_TYPE_HASH_REQUEST    1
#define MSG_TYPE_HASH_RESPONSE   2
#define MSG_TYPE_MODULE_INFO     3
#define MSG_TYPE_BASELINE_UPDATE 4
#define MSG_TYPE_ALERT           5
#define MSG_TYPE_STATUS_QUERY    6
#define MSG_TYPE_STATUS_RESPONSE 7

#define MAX_BASELINE_HASH_LEN 65
#define MAX_MONITORS 3

struct attest_state {
    struct sock *nl_sock;
    u32 user_pid;
    u32 monitor_pids[MAX_MONITORS];
    u8 monitor_count;
    bool monitoring_active;
    char baseline_hash[MAX_BASELINE_HASH_LEN];
    spinlock_t lock;
    unsigned long measurement_count;
    unsigned long alert_count;
    ktime_t last_measurement_time;
};

extern struct attest_state *g_attest_state;

#define ATTEST_LOG_INFO(fmt, ...) \
    pr_info("[ATTEST] " fmt, ##__VA_ARGS__)

#define ATTEST_LOG_WARN(fmt, ...) \
    pr_warn("[ATTEST] " fmt, ##__VA_ARGS__)

#define ATTEST_LOG_ERR(fmt, ...) \
    pr_err("[ATTEST] " fmt, ##__VA_ARGS__)

#define ATTEST_LOG_DEBUG(fmt, ...) \
    pr_debug("[ATTEST] " fmt, ##__VA_ARGS__)

#define NL_LOG_INFO(fmt, ...) \
    pr_info("[ATTEST-NL] " fmt, ##__VA_ARGS__)

#define MEASURE_LOG_INFO(fmt, ...) \
    pr_info("[ATTEST-MEASURE] " fmt, ##__VA_ARGS__)

#define HOOKS_LOG_INFO(fmt, ...) \
    pr_info("[ATTEST-HOOKS] " fmt, ##__VA_ARGS__)

#include "netlink_comm.h"
#include "measure.h"
#include "hooks.h"

static inline void attest_state_lock(void)
{
    if (g_attest_state)
        spin_lock(&g_attest_state->lock);
}

static inline void attest_state_unlock(void)
{
    if (g_attest_state)
        spin_unlock(&g_attest_state->lock);
}

#endif
