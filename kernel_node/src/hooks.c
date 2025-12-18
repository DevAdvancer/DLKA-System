#include "../include/attest_lkm.h"

static struct kprobe kp_do_init_mod;
static struct kprobe kp_free_module;
static struct notifier_block module_nb;

static void broadcast_event(enum hook_event_type ev, const char *msg)
{
        char buf[256];

        snprintf(buf, sizeof(buf),
                 "EVENT_TYPE=%d|DESC=%s|TIME=%lld",
                 ev, msg, ktime_get_real_seconds());

        HOOKS_LOG_INFO("%s\n", msg);

        if (!g_attest_state || !g_attest_state->nl_sock)
                return;

        netlink_send_broadcast(MSG_TYPE_ALERT, buf, strlen(buf) + 1);

        attest_state_lock();
        g_attest_state->alert_count++;
        attest_state_unlock();
}

static int module_event_cb(struct notifier_block *nb,
                           unsigned long action, void *data)
{
        switch (action) {
        case MODULE_STATE_COMING:
                broadcast_event(HOOK_MODULE_LOAD,
                                "Module load attempt (MODULE_STATE_COMING)");
                break;
        case MODULE_STATE_LIVE:
                broadcast_event(HOOK_MODULE_LOAD,
                                "Module load completed (MODULE_STATE_LIVE)");
                break;
        case MODULE_STATE_GOING:
                broadcast_event(HOOK_MODULE_UNLOAD,
                                "Module unload started (MODULE_STATE_GOING)");
                break;
        default:
                break;
        }
        return NOTIFY_OK;
}

int module_notifier_register(void)
{
        module_nb.notifier_call = module_event_cb;
        return register_module_notifier(&module_nb);
}

void module_notifier_unregister(void)
{
        unregister_module_notifier(&module_nb);
}

static int pre_do_init(struct kprobe *p, struct pt_regs *r)
{
        broadcast_event(HOOK_MODULE_LOAD, "Module load attempt (kprobe)");
        return 0;
}

static int pre_free_module(struct kprobe *p, struct pt_regs *r)
{
        broadcast_event(HOOK_MODULE_UNLOAD, "Module unload detected (kprobe)");
        return 0;
}

int hooks_init(void)
{
        if (!g_attest_state)
                return -EINVAL;

        module_notifier_register();

        memset(&kp_do_init_mod, 0, sizeof(kp_do_init_mod));
        kp_do_init_mod.symbol_name = "do_init_module";
        kp_do_init_mod.pre_handler = pre_do_init;
        register_kprobe(&kp_do_init_mod);

        memset(&kp_free_module, 0, sizeof(kp_free_module));
        kp_free_module.symbol_name = "free_module";
        kp_free_module.pre_handler = pre_free_module;
        register_kprobe(&kp_free_module);

        HOOKS_LOG_INFO("Integrity hooks ready\n");

        broadcast_event(HOOK_MODULE_LOAD, "Hooks initialized – test alert");
        return 0;
}

void hooks_exit(void)
{
        broadcast_event(HOOK_MODULE_UNLOAD, "Hooks shutting down");

        unregister_kprobe(&kp_do_init_mod);
        unregister_kprobe(&kp_free_module);
        module_notifier_unregister();

        HOOKS_LOG_INFO("Integrity hooks unregistered\n");
}
