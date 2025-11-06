#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, MAX_EVENTS);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} ssh_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_IP_ADDRESSES);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
} ssh_failure_count SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_IP_ADDRESSES);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
} ssh_attempts SEC(".maps");

// sockaddr_in structure (simplified for IPv4)
struct sockaddr_in {
    __u16 sin_family;      // AF_INET = 2
    __be16 sin_port;       // Port in network byte order
    struct in_addr {
        __be32 s_addr;      // IP address in network byte order
    } sin_addr;
    __u8 sin_zero[8];      // Padding
};

// Hook into tcp_v4_connect to detect SSH connection attempts
// tcp_v4_connect signature: int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
SEC("kprobe/tcp_v4_connect")
int ssh_kprobe_tcp_connect(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct sockaddr *uaddr = (struct sockaddr *)PT_REGS_PARM2(ctx);
    
    if (!sk || !uaddr) return 0;
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    
    // Read sockaddr_in structure
    struct sockaddr_in addr = {};
    bpf_probe_read_kernel(&addr, sizeof(addr), uaddr);
    
    // Check if it's IPv4 (AF_INET = 2)
    if (addr.sin_family != 2) {
        return 0;
    }
    
    // Get destination port (convert from network byte order)
    __u16 dst_port = __builtin_bswap16(addr.sin_port);
    
    // Only process SSH connections (port 22)
    if (dst_port != 22) {
        return 0;
    }
    
    // Get destination IP (we'll use this, but for source IP we need to read from socket)
    __u32 dst_ip = __builtin_bswap32(addr.sin_addr.s_addr);
    
    // Try to get source IP from socket structure
    // Common offsets for skc_rcv_saddr in sock_common (varies by kernel version)
    __u32 src_ip = 0;
    
    // Try reading from common offsets (these are approximate and may need adjustment)
    // Offset 12-16 are common locations for source address in sock_common
    bpf_probe_read_kernel(&src_ip, sizeof(src_ip), (char *)sk + 12);
    if (src_ip == 0) {
        bpf_probe_read_kernel(&src_ip, sizeof(src_ip), (char *)sk + 16);
    }
    
    // If we still don't have source IP, use destination IP as fallback
    // (This means we're tracking the connection target, not the source)
    if (src_ip == 0) {
        src_ip = dst_ip;
    }
    
    // Track attempt
    __u64 *count = bpf_map_lookup_elem(&ssh_attempts, &src_ip);
    __u64 new_count = count ? *count + 1 : 1;
    bpf_map_update_elem(&ssh_attempts, &src_ip, &new_count, BPF_ANY);
    
    // Initialize event structure
    struct ssh_event event = {};
    event.ip = src_ip;
    event.port = dst_port;
    event.pid = pid;
    event.event_type = SSH_ATTEMPT;
    event.timestamp = bpf_ktime_get_ns();
    
    bpf_perf_event_output(ctx, &ssh_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

// Also hook IPv6 connections
SEC("kprobe/tcp_v6_connect")
int ssh_kprobe_tcp_v6_connect(struct pt_regs *ctx)
{
    // Similar to IPv4, but for IPv6
    // For now, we'll focus on IPv4, but this can be extended
    return 0;
}

// Track failed connections via return probe
SEC("kretprobe/tcp_v4_connect")
int ssh_kretprobe_tcp_connect(struct pt_regs *ctx)
{
    // If connection failed (negative return), we could track it here
    // But we need the socket/IP info which is harder to get from kretprobe
    // For now, we'll track all connection attempts and let user-space
    // correlate with auth logs for actual failures
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

