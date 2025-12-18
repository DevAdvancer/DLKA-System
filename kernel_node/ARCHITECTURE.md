# Attest LKM Architecture Documentation

## System Overview

Attest LKM is a kernel-space integrity monitoring system that provides runtime attestation capabilities through cryptographic measurement and event detection.

## Core Components

### 1. Global State Management

**Structure: `attest_state`**

Maintains module-wide state with spinlock protection:

```c
struct attest_state {
    struct sock *nl_sock;              // Netlink socket handle
    u32 user_pid;                      // Primary monitor process ID
    u32 monitor_pids[MAX_MONITORS];    // Multiple monitor support
    u8 monitor_count;                  // Active monitor count
    bool monitoring_active;            // Monitoring status flag
    char baseline_hash[65];            // Reference hash for comparison
    spinlock_t lock;                   // Concurrent access protection
    unsigned long measurement_count;   // Statistics: total measurements
    unsigned long alert_count;         // Statistics: total alerts
    ktime_t last_measurement_time;     // Timestamp tracking
};
```

**Access Pattern:**
- Protected by spinlock for concurrent access
- Single global instance: `g_attest_state`
- Allocated during module initialization
- Freed during module exit

### 2. Measurement Engine

**Purpose:** Compute cryptographic hashes of kernel memory regions

**Implementation Details:**

**Symbol Resolution:**
- Uses kprobe workaround to obtain `kallsyms_lookup_name`
- Required because symbol is not exported in modern kernels
- Registers temporary kprobe to capture function address

**Hash Computation:**
1. Allocate SHA256 transform context
2. Locate kernel text section via `_stext` symbol
3. Sample 4KB of kernel code
4. Compute SHA256 hash
5. Convert to 64-character hex string
6. Update statistics atomically

**Fallback Strategy:**
- If `_stext` unavailable, hash `sys_call_table`
- Final fallback: hash `init_task` structure
- Ensures measurement always succeeds

**Output Format:**
- 64 hexadecimal characters + null terminator
- Example: `a3f5b2c1...` (SHA256 of kernel memory)

### 3. Integrity Hooks

**Detection Mechanisms:**

**Module Notifier (Primary):**
- Registers with kernel module subsystem
- Receives callbacks for all module state changes
- Events: `MODULE_STATE_COMING`, `MODULE_STATE_LIVE`, `MODULE_STATE_GOING`
- Always functional, no symbol dependencies

**Kprobes (Secondary):**
- Probes `do_init_module` for load detection
- Probes `free_module` for unload detection
- May fail on kernels with restricted symbols
- Provides additional granularity when available

**Event Broadcasting:**
- Formats event as structured string: `EVENT_TYPE=X|DESC=...|TIME=...`
- Broadcasts via Netlink multicast
- Increments alert counter atomically

### 4. Netlink Communication

**Socket Configuration:**
- Protocol: `NETLINK_ATTEST (31)`
- Multicast group: `1`
- Input handler: `netlink_recv_msg`

**Message Structure:**

```c
struct attest_msg {
    u32 msg_type;      // Message type identifier
    u32 data_len;      // Payload length
    char data[512];    // Variable payload
} __attribute__((packed));
```

**Communication Patterns:**

**Unicast (Request-Response):**
1. Userspace sends `MSG_TYPE_HASH_REQUEST`
2. Kernel computes hash
3. Kernel replies with `MSG_TYPE_HASH_RESPONSE` to sender PID
4. Direct delivery to requesting process

**Multicast (Alerts):**
1. Kernel detects security event
2. Formats alert message
3. Broadcasts to all subscribed processes
4. Non-blocking, continues if no listeners

**Error Handling:**
- `-ESRCH`: No listeners (normal, ignored)
- `-ENOMEM`: Memory allocation failure
- `-EINVAL`: Invalid parameters

## Initialization Sequence

```
1. attest_init()
   ├─> Allocate global state
   ├─> Initialize spinlock
   ├─> netlink_init()
   │   ├─> Create Netlink socket
   │   └─> Send initialization broadcast
   ├─> measure_init()
   │   ├─> Resolve kallsyms_lookup_name via kprobe
   │   └─> Allocate SHA256 crypto context
   └─> hooks_init()
       ├─> Register module notifier
       ├─> Register kprobe on do_init_module
       ├─> Register kprobe on free_module
       └─> Send test alert
```

## Shutdown Sequence

```
1. attest_exit()
   ├─> hooks_exit()
   │   ├─> Send shutdown alert
   │   ├─> Unregister kprobes
   │   └─> Unregister module notifier
   ├─> measure_exit()
   │   └─> Free SHA256 crypto context
   ├─> netlink_exit()
   │   ├─> Send shutdown broadcast
   │   └─> Release Netlink socket
   └─> Free global state
```

## Data Flow

### Hash Request Flow

```
Userspace                    Kernel
    |                          |
    |--MSG_TYPE_HASH_REQUEST-->|
    |                          |
    |                    [Compute Hash]
    |                          |
    |<--MSG_TYPE_HASH_RESPONSE-|
    |   (SHA256 hex string)    |
```

### Alert Flow

```
Kernel Event              Netlink              Userspace Monitors
     |                       |                        |
[Module Load]                |                        |
     |                       |                        |
[Format Alert]               |                        |
     |                       |                        |
     |--Multicast Broadcast->|                        |
     |                       |--Alert Delivery------->|
     |                       |--Alert Delivery------->|
     |                       |--Alert Delivery------->|
```

## Security Model

**Threat Detection:**
- Unauthorized module loading
- Kernel memory modification
- Runtime integrity violations

**Limitations:**
- Samples only 4KB of kernel text (performance trade-off)
- Cannot detect all rootkit techniques
- Relies on kernel's own integrity for operation

**Trust Assumptions:**
- Kernel is trusted at module load time
- Secure Boot validates module signature
- Kprobes and notifiers function correctly

## Performance Characteristics

**Memory Usage:**
- Global state: ~200 bytes
- Per-hash operation: ~4KB temporary allocation
- Netlink buffers: Dynamic, kernel-managed

**CPU Impact:**
- Hash computation: ~1ms per operation
- Event detection: Negligible overhead
- Netlink communication: Asynchronous, non-blocking

**Scalability:**
- Supports up to 3 concurrent monitors
- Unlimited alert broadcasting
- No persistent storage requirements

## Extension Points

**Adding New Measurements:**
1. Implement measurement function in `measure.c`
2. Add message type to protocol
3. Handle request in `netlink_recv_msg`

**Adding New Hooks:**
1. Define event type in `hooks.h`
2. Register kprobe or notifier in `hooks_init`
3. Call `broadcast_event` on detection

**Protocol Extensions:**
1. Define new message type constant
2. Update `attest_msg` structure if needed
3. Implement handler in `netlink_recv_msg`
4. Update userspace client

## Debugging

**Kernel Logs:**
```bash
# View all module logs
sudo dmesg | grep ATTEST

# Component-specific logs
sudo dmesg | grep "ATTEST-MEASURE"
sudo dmesg | grep "ATTEST-HOOKS"
sudo dmesg | grep "ATTEST-NL"
```

**Statistics:**
- Measurement count tracked in `g_attest_state->measurement_count`
- Alert count tracked in `g_attest_state->alert_count`
- Logged during module unload

**Common Issues:**

**Kprobe registration fails:**
- Expected on hardened kernels
- Module notifier still functions
- Non-critical for basic operation

**Netlink send returns -ESRCH:**
- No userspace listeners
- Normal during initialization
- Alerts are queued and dropped

**Hash computation fails:**
- Symbol resolution failed
- Fallback mechanisms activate
- Check dmesg for specific error
