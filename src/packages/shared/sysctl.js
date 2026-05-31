export const SYSCTL_NETWORK = `
# Refuse ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Refuse sending redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Refuse source-routed packets
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Log martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# SYN cookies
net.ipv4.tcp_syncookies = 1

# Reverse path filtering
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP broadcasts
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Disable IP forwarding unless VPN/router
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# TCP hardening
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
`.trim();

export const SYSCTL_KERNEL = `
# ASLR
kernel.randomize_va_space = 2

# Restrict dmesg
kernel.dmesg_restrict = 1

# Restrict kernel pointers in /proc
kernel.kptr_restrict = 2

# Restrict ptrace
kernel.yama.ptrace_scope = 2

# Disable magic SysRq
kernel.sysrq = 0

# Restrict unprivileged user namespaces
kernel.unprivileged_userns_clone = 0

# Core dumps
kernel.core_uses_pid = 1
fs.suid_dumpable = 0

# Perf event paranoia
kernel.perf_event_paranoid = 3

# Restrict BPF
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
`.trim();

export const SYSCTL_FS = `
# Protect hardlinks and symlinks
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
`.trim();
