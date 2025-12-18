#ifndef NETLINK_COMM_H
#define NETLINK_COMM_H

#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/net_namespace.h>

#define MSG_TYPE_ACK 6

struct attest_msg {
    u32 msg_type;
    u32 data_len;
    char data[512];
} __attribute__((packed));

int netlink_init(void);
void netlink_exit(void);
void netlink_send_msg(u32 msg_type, const char *data, size_t len);
int netlink_send_unicast(u32 msg_type, const char *data, size_t len, pid_t pid);
int netlink_send_broadcast(u32 msg_type, const char *data, size_t len);
void netlink_recv_msg(struct sk_buff *skb);

#endif
