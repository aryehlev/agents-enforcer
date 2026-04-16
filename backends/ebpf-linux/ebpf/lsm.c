// SPDX-License-Identifier: MIT
/*
 * Agent Gateway Enforcer - eBPF LSM Program for File Access Control
 *
 * This eBPF program uses LSM hooks to intercept file operations
 * and block access for specified processes (e.g., "opencode" agents).
 */

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Maximum path length to check
#define MAX_PATH_LEN 256
#define MAX_COMM_LEN 16

// Event types for userspace
#define EVENT_FILE_OPEN 1
#define EVENT_FILE_BLOCKED 2

// Structure for blocked process names
struct blocked_process {
    char comm[MAX_COMM_LEN];
};

// Structure for blocked paths
struct blocked_path {
    char path[MAX_PATH_LEN];
    __u32 len;
};

// Event structure sent to userspace
struct file_event {
    __u32 event_type;
    __u32 pid;
    __u32 uid;
    char comm[MAX_COMM_LEN];
    char path[MAX_PATH_LEN];
    __s32 action; // 0 = allowed, -1 = blocked
};

// Map: blocked process names (indexed by slot)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, struct blocked_process);
} blocked_processes SEC(".maps");

// Map: blocked paths (indexed by slot)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, struct blocked_path);
} blocked_paths SEC(".maps");

// Map: configuration flags
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} config SEC(".maps");

// Ring buffer for events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Configuration keys
#define CONFIG_ENABLED 0
#define CONFIG_BLOCK_ALL_PATHS 1
#define CONFIG_NUM_BLOCKED_PROCS 2
#define CONFIG_NUM_BLOCKED_PATHS 3

// Helper: Check if current process name matches a blocked process
static __always_inline int is_blocked_process(char *comm) {
    __u32 key = CONFIG_NUM_BLOCKED_PROCS;
    __u32 *num_procs = bpf_map_lookup_elem(&config, &key);
    if (!num_procs || *num_procs == 0)
        return 0;

    #pragma unroll
    for (__u32 i = 0; i < 16; i++) {
        if (i >= *num_procs)
            break;

        struct blocked_process *bp = bpf_map_lookup_elem(&blocked_processes, &i);
        if (!bp)
            continue;

        // Simple prefix comparison
        int match = 1;
        #pragma unroll
        for (int j = 0; j < MAX_COMM_LEN; j++) {
            if (bp->comm[j] == '\0')
                break;
            if (comm[j] != bp->comm[j]) {
                match = 0;
                break;
            }
        }
        if (match)
            return 1;
    }
    return 0;
}

// Helper: Check if path should be blocked
static __always_inline int is_blocked_path(const char *path) {
    __u32 key = CONFIG_BLOCK_ALL_PATHS;
    __u32 *block_all = bpf_map_lookup_elem(&config, &key);

    // If block_all is set, block everything
    if (block_all && *block_all)
        return 1;

    // Check specific blocked paths
    key = CONFIG_NUM_BLOCKED_PATHS;
    __u32 *num_paths = bpf_map_lookup_elem(&config, &key);
    if (!num_paths || *num_paths == 0)
        return 1;  // Default: block all if no paths configured

    #pragma unroll
    for (__u32 i = 0; i < 64; i++) {
        if (i >= *num_paths)
            break;

        struct blocked_path *bp = bpf_map_lookup_elem(&blocked_paths, &i);
        if (!bp || bp->len == 0)
            continue;

        // Check if path starts with blocked path prefix
        int match = 1;
        #pragma unroll
        for (__u32 j = 0; j < MAX_PATH_LEN && j < bp->len; j++) {
            if (bp->path[j] == '\0')
                break;
            // Bounds check for path access
            if (j < MAX_PATH_LEN) {
                char c;
                bpf_probe_read_kernel(&c, 1, &path[j]);
                if (c != bp->path[j]) {
                    match = 0;
                    break;
                }
            }
        }
        if (match)
            return 1;
    }
    return 0;
}

// Helper: Send event to userspace
static __always_inline void send_event(__u32 event_type, __u32 pid, __u32 uid,
                                        char *comm, const char *path, __s32 action) {
    struct file_event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;

    e->event_type = event_type;
    e->pid = pid;
    e->uid = uid;
    e->action = action;

    // Copy comm
    #pragma unroll
    for (int i = 0; i < MAX_COMM_LEN; i++) {
        e->comm[i] = comm[i];
    }

    // Copy path (with bounds checking)
    bpf_probe_read_kernel_str(e->path, MAX_PATH_LEN, path);

    bpf_ringbuf_submit(e, 0);
}

/*
 * LSM hook: file_open
 *
 * Called when a file is opened. We check if the calling process
 * is a blocked agent and if so, deny the operation.
 */
SEC("lsm/file_open")
int BPF_PROG(file_open_block, struct file *file) {
    // Check if enforcement is enabled
    __u32 key = CONFIG_ENABLED;
    __u32 *enabled = bpf_map_lookup_elem(&config, &key);
    if (!enabled || !*enabled)
        return 0;  // Allow if not enabled

    // Get current process info
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    char comm[MAX_COMM_LEN];
    bpf_get_current_comm(comm, sizeof(comm));

    // Check if this is a blocked process
    if (!is_blocked_process(comm))
        return 0;  // Allow non-blocked processes

    // Get file path
    const char *path = NULL;
    struct path f_path;

    // Read the file path from the file structure
    bpf_probe_read_kernel(&f_path, sizeof(f_path), &file->f_path);

    // For simplicity, we'll use the dentry name
    // In production, you'd want to reconstruct the full path
    struct dentry *dentry;
    bpf_probe_read_kernel(&dentry, sizeof(dentry), &f_path.dentry);

    struct qstr d_name;
    bpf_probe_read_kernel(&d_name, sizeof(d_name), &dentry->d_name);

    path = d_name.name;

    // Check if path should be blocked
    if (is_blocked_path(path)) {
        // Send blocked event
        send_event(EVENT_FILE_BLOCKED, pid, uid, comm, path, -1);
        return -EPERM;  // Permission denied
    }

    // Allow access
    send_event(EVENT_FILE_OPEN, pid, uid, comm, path, 0);
    return 0;
}

/*
 * LSM hook: file_permission
 *
 * Called for various file operations (read, write, etc.)
 */
SEC("lsm/file_permission")
int BPF_PROG(file_permission_block, struct file *file, int mask) {
    // Check if enforcement is enabled
    __u32 key = CONFIG_ENABLED;
    __u32 *enabled = bpf_map_lookup_elem(&config, &key);
    if (!enabled || !*enabled)
        return 0;

    // Get current process info
    char comm[MAX_COMM_LEN];
    bpf_get_current_comm(comm, sizeof(comm));

    // Check if this is a blocked process
    if (!is_blocked_process(comm))
        return 0;

    // For blocked processes, deny write operations on sensitive files
    // mask: MAY_READ=4, MAY_WRITE=2, MAY_EXEC=1
    if (mask & 2) {  // Write operation
        return -EPERM;
    }

    return 0;
}

char LICENSE[] SEC("license") = "MIT";
