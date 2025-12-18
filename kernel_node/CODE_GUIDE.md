# Code Structure Guide

## File Organization

### Header Files (`include/`)

#### `attest_lkm.h` - Main Header
**Purpose:** Central definitions and state management

**Key Definitions:**
- `ATTEST_VERSION_*` - Module version constants
- `NETLINK_ATTEST` - Netlink protocol number (31)
- `MSG_TYPE_*` - Message type constants for protocol
- `struct attest_state` - Global state structure
- Logging macros: `ATTEST_LOG_INFO`, `ATTEST_LOG_ERR`, etc.

**Global State:**
```c
extern struct attest_state *g_attest_state;
```

**Utility Functions:**
- `attest_state_lock()` - Acquire spinlock
- `attest_state_unlock()` - Release spinlock

#### `measure.h` - Measurement Interface
**Purpose:** Cryptographic measurement API

**Constants:**
- `HASH_OUTPUT_SIZE` - 65 bytes (64 hex + null)

**Functions:**
- `measure_init()` - Initialize crypto subsystem
- `measure_exit()` - Cleanup crypto resources
- `compute_kernel_hash()` - Hash kernel memory
- `compute_module_hash()` - Hash specific module (placeholder)
- `get_kernel_text_bounds()` - Locate kernel text section

#### `hooks.h` - Integrity Monitoring Interface
**Purpose:** Event detection and alerting

**Event Types:**
```c
enum hook_event_type {
    HOOK_MODULE_LOAD,
    HOOK_MODULE_UNLOAD,
    HOOK_SYSCALL_TABLE_MODIFY,
    HOOK_TEXT_WRITE,
};
```

**Functions:**
- `hooks_init()` - Register kprobes and notifiers
- `hooks_exit()` - Unregister all hooks
- `module_notifier_register()` - Setup module notifier
- `module_notifier_unregister()` - Cleanup notifier

#### `netlink_comm.h` - Communication Interface
**Purpose:** Kernel-userspace messaging

**Message Structure:**
```c
struct attest_msg {
    u32 msg_type;
    u32 data_len;
    char data[512];
} __attribute__((packed));
```

**Functions:**
- `netlink_init()` - Create Netlink socket
- `netlink_exit()` - Release socket
- `netlink_send_unicast()` - Send to specific PID
- `netlink_send_broadcast()` - Send to all listeners
- `netlink_recv_msg()` - Receive callback

### Source Files (`src/`)

#### `attest_lkm.c` - Module Entry Point
**Purpose:** Module lifecycle management

**Key Functions:**

`attest_init()` - Module initialization
1. Allocate global state
2. Initialize spinlock
3. Initialize Netlink subsystem
4. Initialize measurement engine
5. Initialize integrity hooks
6. Error handling with proper cleanup

`attest_exit()` - Module cleanup
1. Shutdown hooks
2. Shutdown measurement engine
3. Shutdown Netlink
4. Free global state
5. Log statistics

**Module Metadata:**
- License: GPL
- Authors: Abhirup Kumar & Sujal Kr Sil
- Description: Distributed Kernel Runtime Attestation Module
- Version: 1.0.0

#### `measure.c` - Cryptographic Measurement
**Purpose:** Hash computatioementation

**Static Variables:**
- `sha256_tfm` - Crypto transform context
- `my_kallsyms_lookup_name` - Function pointer for symbol lookup

**Key Functions:**

`init_kallsyms_lookup()` - Resolve kallsyms_lookup_name
- Uses kprobe workaround
- Required for symbol resolution
- Unregisters kprobe after capturing address

`get_kernel_text_bounds()` - Locate kernel code
- Resolves `_stext` symbol
- Returns start and end addresses
- Samples 4KB region

`compute_kernel_hash()` - Main hashing function
1. Allocate hash descriptor
2. Initialize SHA256 context
3. Locate kernel text section
4. Fallback to sys_call_table or init_task if needed
5. Update hash with memory contents
6. Finalize and convert to hex string
7. Update statistics atomically

`measure_init()` - Initialize subsystem
- Resolve kallsyms_lookup_name
- Allocate SHA256 crypto transform

`measure_exit()` - Cleanup
- Free crypto transform

#### `hooks.c` - Integrity Monitoring
**Purpose:** Event detection and broadcasting

**Static Variables:**
- `kp_do_init_mod` - Kprobe for module initialization
- `kp_free_module` - Kprobe for module cleanup
- `module_nb` - Module notifier block

**Key Functions:**

`broadcast_event()` - Send alert
1. Format event string: `EVENT_TYPE=X|DESC=...|TIME=...`
2. Log to kernel log
3. Send via Netlink multicast
4. Increment alert counter

`module_event_cb()` - Module notifier callback
- Handles `MODULE_STATE_COMING` (load attempt)
- Handles `MODULE_STATE_LIVE` (load complete)
- Handles `MODULE_STATE_GOING` (unload)
- Broadcasts event for each state change

`pre_do_init()` - Kprobe handler for module init
- Called before `do_init_module`
- Broadcasts load attempt

`pre_free_module()` - Kprobe handler for module free
- Called before `free_module`
- Broadcasts unload detection

`hooks_init()` - Setup monitoring
1. Register module notifier (always works)
2. Register kprobe on do_init_module (may fail)
3. Register kprobe on free_module (may fail)
4. Send test alert

`hooks_exit()` - Cleanup monitoring
1. Send shutdown alert
2. Unregister kprobes
3. Unregister module notifier

#### `netlink_comm.c` - Communication Layer
**Purpose:** Netlink protocol implementation

**Constants:**
- `NETLINK_ATTEST_GROUP` - Multicast group ID (1)

**Key Functions:**

`netlink_recv_msg()` - Message handler
- Extracts message from socket buffer
- Switches on message type:
  - `MSG_TYPE_HASH_REQUEST`: Compute and return hash
  - `MSG_TYPE_BASELINE_UPDATE`: Store baseline hash
  - Others: Log warning
- Sends responses via unicast

`netlink_send_unicast()` - Direct messaging
1. Allocate socket buffer
2. Construct Netlink message header
3. Fill attest_msg structure
4. Send to specific PID
5. Handle errors (EINVAL, ENOMEM)

`netlink_send_broadcast()` - Multicast messaging
1. Allocate socket buffer
2. Construct message
3. Send to multicast group
4. Ignore -ESRCH (no listeners)
5. Log other errors

`netlink_send_msg()` - Routing wrapper
- Alerts → broadcast
- Responses → unicast to stored PID
- Fallback → broadcast

`netlink_init()` - Socket creation
1. Configure Netlink parameters
2. Create kernel socket
3. Send initialization broadcast

`netlink_exit()` - Socket cleanup
1. Send shutdown broadcast
2. Release socket

### Build System

#### `Makefile`
**Purpose:** Kernel module build configuration

**Variables:**
- `obj-m` - Module object name
- `attest_lkm-objs` - Source file list
- `KERNEL_VERSION` - Target kernel version
- `KDIR` - Kernel build directory
- `SIGN_FILE` - Module signing script

**Targets:**
- `all` - Build module
- `clean` - Remove build artifacts
- `install` - Load module
- `uninstall` - Unload module
- `reload` - Unload and reload
- `sign` - Sign module with MOK

### Scripts

#### `MOK_Gen.sh`
Generates RSA-2048 signing keys for Secure Boot

#### `build_load.sh`
Convenience script: clean, build, sign, load, verify

#### `install.sh`
Configures systemd service for auto-start on boot

#### `cleanup_attest.sh`
Unloads module and schedules MOK deletion

#### `test_monitor.sh`
Runs Python test client with proper permissions

### Test Files (`test/`)

#### `monitor_test.py`
Example userspace client demonstrating:
- Netlink socket creation
- Multicast group subscription
- Hash request/response
- Alert reception

#### `netlink_test.py`
Protocol testing and validation

## Code Flow Examples

### Module Load Sequence
```
1. User: insmod attest_lkm.ko
2. Kernel: attest_init()
3. Allocate g_attest_state
4. netlink_init() → Create socket
5. measure_init() → Setup crypto
6. hooks_init() → Register monitors
7. Send "Module loaded" to dmesg
```

### Hash Request Sequence
```
1. Userspace: Send MSG_TYPE_HASH_REQUEST
2. Kernel: netlink_recv_msg() receives
3. Call compute_kernel_hash()
4. Locate kernel text via _stext
5. Compute SHA256 of 4KB sample
6. Convert to hex string
7. Send MSG_TYPE_HASH_RESPONSE
8. Userspace: Receive hash
```

### Module Load Detection
```
1. Another module loads
2. Kernel: module_event_cb() triggered
3. Event: MODULE_STATE_COMING
4. broadcast_event() called
5. Format: "EVENT_TYPE=1|DESC=...|TIME=..."
6. netlink_send_broadcast()
7. All monitors receive alert
```

## Extending the Code

### Add New Measurement Type

1. Define message type in `attest_lkm.h`:
```c
#define MSG_TYPE_PROCESS_HASH 8
```

2. Implement function in `measure.c`:
```c
int compute_process_hash(pid_t pid, char *hash_output, size_t out_len);
```

3. Handle in `netlink_recv_msg()`:
```c
case MSG_TYPE_PROCESS_HASH:
    compute_process_hash(msg->pid, hash, sizeof(hash));
    netlink_send_unicast(MSG_TYPE_HASH_RESPONSE, hash, ...);
    break;
```

### Add New Hook Type

1. Define event in `hooks.h`:
```c
HOOK_FILE_OPEN = 5,
```

2. Register kprobe in `hooks_init()`:
```c
kp_file_open.symbol_name = "do_sys_open";
kp_file_open.pre_handler = pre_file_open;
register_kprobe(&kp_file_open);
```

3. Implement handler:
```c
static int pre_file_open(struct kprobe *p, struct pt_regs *r) {
    broadcast_event(HOOK_FILE_OPEN, "File opened");
    return 0;
}
```

## Best Practices

**Memory Management:**
- Always check allocation return values
- Use `GFP_KERNEL` for sleepable contexts
- Use `GFP_ATOMIC` for interrupt contexts
- Free resources in reverse order of allocation

**Locking:**
- Use spinlocks for short critical sections
- Always unlock in error paths
- Use `attest_state_lock()` wrapper for consistency

**Error Handling:**
- Return negative error codes
- Use goto labels for cleanup
- Log errors with `ATTEST_LOG_ERR`

**Logging:**
- Use component-specific macros
- Include relevant context in messages
- Use appropriate log levels

**Testing:**
- Test module load/unload cycles
- Verify Netlink communication
- Check error paths
- Monitor kernel logs for warnings
