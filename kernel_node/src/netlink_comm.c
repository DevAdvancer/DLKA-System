#include "../include/attest_lkm.h"

#define NETLINK_ATTEST_GROUP 1

void netlink_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    struct attest_msg *msg;
    pid_t sender_pid;

    nlh = (struct nlmsghdr *)skb->data;
    msg = (struct attest_msg *)nlmsg_data(nlh);
    sender_pid = nlh->nlmsg_pid;

    pr_info("[ATTEST-NL] Received message type: %u from PID: %u\n",
            msg->msg_type, sender_pid);

    switch (msg->msg_type) {
        case MSG_TYPE_HASH_REQUEST: {
            char hash[65] = {0};
            int ret = compute_kernel_hash(hash, sizeof(hash));

            if (ret == 0) {
                netlink_send_unicast(MSG_TYPE_HASH_RESPONSE, hash,
                                   strlen(hash) + 1, sender_pid);
            } else {
                netlink_send_unicast(MSG_TYPE_HASH_RESPONSE, "ERROR",
                                   6, sender_pid);
            }
            break;
        }

        case MSG_TYPE_BASELINE_UPDATE:
            if (msg->data_len < sizeof(g_attest_state->baseline_hash)) {
                memcpy(g_attest_state->baseline_hash, msg->data, msg->data_len);
                pr_info("[ATTEST-NL] Baseline hash updated\n");

                netlink_send_unicast(MSG_TYPE_ACK, "BASELINE_SET",
                                   13, sender_pid);
            }
            break;

        default:
            pr_warn("[ATTEST-NL] Unknown message type: %u\n", msg->msg_type);
    }
}

int netlink_send_unicast(u32 msg_type, const char *data, size_t len, pid_t pid)
{
    struct sk_buff *skb_out;
    struct nlmsghdr *nlh;
    struct attest_msg *msg;
    int msg_size;
    int ret;

    if (!g_attest_state->nl_sock) {
        pr_warn("[ATTEST-NL] Netlink socket not initialized\n");
        return -ENODEV;
    }

    if (pid == 0) {
        pr_warn("[ATTEST-NL] Invalid PID for unicast\n");
        return -EINVAL;
    }

    msg_size = sizeof(struct attest_msg);

    skb_out = nlmsg_new(msg_size, GFP_ATOMIC);
    if (!skb_out) {
        pr_err("[ATTEST-NL] Failed to allocate skb for unicast\n");
        return -ENOMEM;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    if (!nlh) {
        kfree_skb(skb_out);
        return -EMSGSIZE;
    }

    msg = nlmsg_data(nlh);
    msg->msg_type = msg_type;
    msg->data_len = len;

    if (len > sizeof(msg->data)) {
        len = sizeof(msg->data);
    }
    memcpy(msg->data, data, len);

    ret = nlmsg_unicast(g_attest_state->nl_sock, skb_out, pid);

    if (ret < 0) {
        pr_err("[ATTEST-NL] Failed to send unicast to PID %u: %d\n", pid, ret);
    } else {
        pr_debug("[ATTEST-NL] Sent unicast message type %u to PID %u\n", msg_type, pid);
    }

    return ret;
}

int netlink_send_broadcast(u32 msg_type, const char *data, size_t len)
{
    struct sk_buff *skb_out;
    struct nlmsghdr *nlh;
    struct attest_msg *msg;
    int msg_size;
    int ret;

    if (!g_attest_state->nl_sock) {
        pr_warn("[ATTEST-NL] Netlink socket not initialized\n");
        return -ENODEV;
    }

    msg_size = sizeof(struct attest_msg);

    skb_out = nlmsg_new(msg_size, GFP_ATOMIC);
    if (!skb_out) {
        pr_err("[ATTEST-NL] Failed to allocate skb for broadcast\n");
        return -ENOMEM;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    if (!nlh) {
        kfree_skb(skb_out);
        return -EMSGSIZE;
    }

    msg = nlmsg_data(nlh);
    msg->msg_type = msg_type;
    msg->data_len = len;

    if (len > sizeof(msg->data)) {
        len = sizeof(msg->data);
    }
    memcpy(msg->data, data, len);

    ret = nlmsg_multicast(g_attest_state->nl_sock, skb_out, 0,
                         NETLINK_ATTEST_GROUP, GFP_ATOMIC);

    if (ret < 0) {
        if (ret == -ESRCH) {
            pr_debug("[ATTEST-NL] No listeners for broadcast (normal)\n");
        } else {
            pr_err("[ATTEST-NL] Failed to broadcast: %d\n", ret);
        }
    } else {
        pr_info("[ATTEST-NL] Broadcast alert sent (type=%u, len=%zu)\n",
                msg_type, len);
    }

    return ret;
}

void netlink_send_msg(u32 msg_type, const char *data, size_t len)
{
    if (msg_type == MSG_TYPE_ALERT) {
        netlink_send_broadcast(msg_type, data, len);
    }
    else if (g_attest_state->user_pid) {
        netlink_send_unicast(msg_type, data, len, g_attest_state->user_pid);
    }
    else {
        netlink_send_broadcast(msg_type, data, len);
    }
}

int netlink_init(void)
{
    struct netlink_kernel_cfg cfg = {
        .input = netlink_recv_msg,
        .groups = 1,
    };

    g_attest_state->nl_sock = netlink_kernel_create(&init_net, NETLINK_ATTEST, &cfg);

    if (!g_attest_state->nl_sock) {
        pr_err("[ATTEST-NL] Failed to create netlink socket\n");
        return -ENOMEM;
    }

    pr_info("[ATTEST-NL] Netlink socket created (protocol: %d, groups: 1)\n",
            NETLINK_ATTEST);

    netlink_send_broadcast(MSG_TYPE_ALERT, "Netlink initialized", 19);

    return 0;
}

void netlink_exit(void)
{
    if (g_attest_state->nl_sock) {
        netlink_send_broadcast(MSG_TYPE_ALERT, "Module shutting down", 20);

        netlink_kernel_release(g_attest_state->nl_sock);
        pr_info("[ATTEST-NL] Netlink socket released\n");
    }
}
