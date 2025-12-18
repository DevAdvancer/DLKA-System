#include "../include/attest_lkm.h"
#include <linux/timer.h>
#include <linux/jiffies.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Abhirup Kumar & Sujal Kr Sil");
MODULE_DESCRIPTION("Distributed Kernel Runtime Attestation Module");
MODULE_VERSION("1.0.0");

struct attest_state *g_attest_state = NULL;

static unsigned int measurement_interval = 10;
module_param(measurement_interval, uint, 0644);
MODULE_PARM_DESC(measurement_interval, "Measurement interval in seconds (default: 10)");

static bool periodic_enabled = true;
module_param(periodic_enabled, bool, 0644);
MODULE_PARM_DESC(periodic_enabled, "Enable periodic measurements (default: true)");

static struct timer_list measurement_timer;

static void periodic_measurement_callback(struct timer_list *t)
{
    char hash[65] = {0};
    int ret;
    char alert_msg[256];

    if (!periodic_enabled || !g_attest_state) {
        goto reschedule;
    }

    ATTEST_LOG_DEBUG("Periodic measurement triggered\n");

    ret = compute_kernel_hash(hash, sizeof(hash));

    if (ret == 0) {
        ATTEST_LOG_INFO("Periodic hash: %.16s...\n", hash);

        netlink_send_broadcast(MSG_TYPE_HASH_RESPONSE, hash, strlen(hash) + 1);

        attest_state_lock();
        if (g_attest_state->baseline_hash[0] != '\0') {
            if (strcmp(hash, g_attest_state->baseline_hash) != 0) {
                snprintf(alert_msg, sizeof(alert_msg),
                        "HASH_MISMATCH|Expected=%.16s...|Current=%.16s...",
                        g_attest_state->baseline_hash, hash);

                ATTEST_LOG_WARN("Hash mismatch detected!\n");
                ATTEST_LOG_WARN("  Expected: %.16s...\n", g_attest_state->baseline_hash);
                ATTEST_LOG_WARN("  Current:  %.16s...\n", hash);

                netlink_send_broadcast(MSG_TYPE_ALERT, alert_msg, strlen(alert_msg) + 1);
                g_attest_state->alert_count++;
            }
        } else {
            strncpy(g_attest_state->baseline_hash, hash,
                   sizeof(g_attest_state->baseline_hash) - 1);
            g_attest_state->baseline_hash[sizeof(g_attest_state->baseline_hash) - 1] = '\0';

            ATTEST_LOG_INFO("Baseline established: %.16s...\n", hash);
        }
        attest_state_unlock();

    } else {
        ATTEST_LOG_ERR("Failed to compute hash: %d\n", ret);
        netlink_send_broadcast(MSG_TYPE_HASH_RESPONSE, "ERROR", 6);
    }

reschedule:
    if (periodic_enabled) {
        mod_timer(&measurement_timer,
                 jiffies + msecs_to_jiffies(measurement_interval * 1000));
    }
}

static int start_periodic_measurements(void)
{
    if (!periodic_enabled) {
        ATTEST_LOG_INFO("Periodic measurements disabled\n");
        return 0;
    }

    timer_setup(&measurement_timer, periodic_measurement_callback, 0);
    mod_timer(&measurement_timer,
             jiffies + msecs_to_jiffies(measurement_interval * 1000));

    ATTEST_LOG_INFO("Periodic measurements started (interval: %u seconds)\n",
                   measurement_interval);
    return 0;
}

static void stop_periodic_measurements(void)
{
    if (timer_pending(&measurement_timer)) {
        del_timer_sync(&measurement_timer);
        ATTEST_LOG_INFO("Periodic measurements stopped\n");
    }
}

static int __init attest_init(void)
{
    int ret;

    ATTEST_LOG_INFO("Initializing v%d.%d.%d\n",
                    ATTEST_VERSION_MAJOR,
                    ATTEST_VERSION_MINOR,
                    ATTEST_VERSION_PATCH);

    ATTEST_LOG_INFO("Config: interval=%u sec, periodic=%s\n",
                   measurement_interval,
                   periodic_enabled ? "enabled" : "disabled");

    g_attest_state = kzalloc(sizeof(struct attest_state), GFP_KERNEL);
    if (!g_attest_state) {
        ATTEST_LOG_ERR("Failed to allocate state structure\n");
        return -ENOMEM;
    }

    spin_lock_init(&g_attest_state->lock);
    g_attest_state->monitoring_active = false;
    g_attest_state->user_pid = 0;
    g_attest_state->monitor_count = 0;
    g_attest_state->measurement_count = 0;
    g_attest_state->alert_count = 0;
    memset(g_attest_state->baseline_hash, 0, sizeof(g_attest_state->baseline_hash));

    ret = netlink_init();
    if (ret < 0) {
        ATTEST_LOG_ERR("Netlink initialization failed: %d\n", ret);
        goto err_netlink;
    }

    ret = measure_init();
    if (ret < 0) {
        ATTEST_LOG_ERR("Measurement engine initialization failed: %d\n", ret);
        goto err_measure;
    }

    ret = hooks_init();
    if (ret < 0) {
        ATTEST_LOG_ERR("Hooks initialization failed: %d\n", ret);
        goto err_hooks;
    }

    ret = start_periodic_measurements();
    if (ret < 0) {
        ATTEST_LOG_ERR("Failed to start periodic measurements: %d\n", ret);
        goto err_timer;
    }

    ATTEST_LOG_INFO("Module loaded successfully\n");
    return 0;

err_timer:
    hooks_exit();
err_hooks:
    measure_exit();
err_measure:
    netlink_exit();
err_netlink:
    kfree(g_attest_state);
    g_attest_state = NULL;
    return ret;
}

static void __exit attest_exit(void)
{
    ATTEST_LOG_INFO("Unloading module (measurements: %lu, alerts: %lu)\n",
                    g_attest_state ? g_attest_state->measurement_count : 0,
                    g_attest_state ? g_attest_state->alert_count : 0);

    stop_periodic_measurements();
    hooks_exit();
    measure_exit();
    netlink_exit();

    if (g_attest_state) {
        kfree(g_attest_state);
        g_attest_state = NULL;
    }

    ATTEST_LOG_INFO("Module unloaded\n");
}

module_init(attest_init);
module_exit(attest_exit);
