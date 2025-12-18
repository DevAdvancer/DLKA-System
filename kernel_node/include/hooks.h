#ifndef HOOKS_H
#define HOOKS_H

#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/module.h>
#include <linux/moduleloader.h>
#include <linux/tracepoint.h>

#define HOOKS_LOG_DEBUG(fmt, ...) \
        pr_debug("[ATTEST-HOOKS] " fmt, ##__VA_ARGS__)

enum hook_event_type {
        HOOK_MODULE_LOAD = 1,
        HOOK_MODULE_UNLOAD,
        HOOK_SYSCALL_TABLE_MODIFY,
        HOOK_TEXT_WRITE,
};

int  hooks_init(void);
void hooks_exit(void);
void send_hook_alert(enum hook_event_type type, const char *desc);
int  module_notifier_register(void);
void module_notifier_unregister(void);

#endif
