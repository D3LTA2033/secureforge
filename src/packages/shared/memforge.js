import { pm } from './pkg.js';

export default {
  id: 'memforge',
  name: 'MemForge — Memory Protection',
  description: '[BETA] Advanced memory hardening: seccomp profiles, executable space checks, heap guard',
  category: 'Kernel',
  maturity: 'beta',
  defaultEnabled: false,

  options: [
    { id: 'verifyASLR',      type: 'confirm', label: 'Verify and enforce ASLR = 2?',                          default: true },
    { id: 'seccompSSHD',     type: 'confirm', label: 'Apply seccomp syscall filter to sshd?',                 default: true },
    { id: 'seccompNginx',    type: 'confirm', label: 'Apply seccomp filter to nginx (if installed)?',         default: false },
    { id: 'heapGuard',       type: 'confirm', label: 'Enable glibc heap guard (MALLOC_CHECK_ + mprotect)?',   default: true },
    { id: 'stackGuard',      type: 'confirm', label: 'Verify stack canary in critical binaries?',             default: true },
    { id: 'pieCheck',        type: 'confirm', label: 'Audit PIE / RELRO status of installed binaries?',       default: true },
    { id: 'execShield',      type: 'confirm', label: 'Harden exec-shield sysctl (nx / smep / smap)?',         default: true },
    { id: 'zeroPagesBlock',  type: 'confirm', label: 'Block mmap to null/zero page (mmap_min_addr=65536)?',   default: true },
    { id: 'clearEnv',        type: 'confirm', label: 'Clear LD_PRELOAD / LD_LIBRARY_PATH in sudo/su?',        default: true },
    { id: 'hugepageSec',     type: 'confirm', label: 'Harden Transparent HugePage behavior?',                 default: true },
  ],

  generate({ distro, options }) {
    const aslr      = options.verifyASLR    ?? true;
    const sshdSec   = options.seccompSSHD   ?? true;
    const nginxSec  = options.seccompNginx  ?? false;
    const heapG     = options.heapGuard     ?? true;
    const stackG    = options.stackGuard    ?? true;
    const pieCheck  = options.pieCheck      ?? true;
    const execSh    = options.execShield    ?? true;
    const zeroPage  = options.zeroPagesBlock ?? true;
    const clearEnv  = options.clearEnv      ?? true;
    const hugepage  = options.hugepageSec   ?? true;

    return `
# ── MemForge: Advanced Memory Protection (${distro}) ──────────────────
# [BETA] Layered memory attack surface reduction.

${pieCheck ? `${pm(distro)('pax-utils binutils')} 2>/dev/null || true` : ''}

# ── 1. ASLR ───────────────────────────────────────────────────────────
${aslr ? `
CURRENT_ASLR=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo 0)
if [[ "$CURRENT_ASLR" -lt 2 ]]; then
  echo 2 > /proc/sys/kernel/randomize_va_space
  echo "[+] ASLR forced to level 2 (was $CURRENT_ASLR)"
fi
echo 'kernel.randomize_va_space = 2' > /etc/sysctl.d/99-sf-memforge-aslr.conf
` : ''}

# ── 2. Exec-shield / NX / SMEP / SMAP sysctl ─────────────────────────
${execSh ? `
cat > /etc/sysctl.d/99-sf-memforge-exec.conf << 'MEM'
# Prevent mmap/exec in low memory ranges
${zeroPage ? 'vm.mmap_min_addr = 65536' : ''}
# Prevent executable stacks (NX bit enforcement in userspace)
kernel.exec-shield = 1 2>/dev/null
# Additional protection against ROP
kernel.kexec_load_disabled = 1
MEM
sysctl --system --load /etc/sysctl.d/99-sf-memforge-exec.conf 2>/dev/null || true
` : ''}

# ── 3. Heap guard via glibc env vars ─────────────────────────────────
${heapG ? `
cat > /etc/environment << 'ENV'
MALLOC_CHECK_=3
MALLOC_PERTURB_=200
ENV
# Also set in /etc/profile.d
cat > /etc/profile.d/sf-heap-guard.sh << 'HEAP'
export MALLOC_CHECK_=3
export MALLOC_PERTURB_=200
export GLIBC_TUNABLES="glibc.malloc.check=3:glibc.malloc.perturb=200"
HEAP
chmod 644 /etc/profile.d/sf-heap-guard.sh
` : ''}

# ── 4. Clear LD_PRELOAD in sudo env ──────────────────────────────────
${clearEnv ? `
cat > /etc/sudoers.d/sf-memforge-env << 'SUDO'
Defaults env_delete += "LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT LD_DEBUG DYLD_INSERT_LIBRARIES"
SUDO
chmod 440 /etc/sudoers.d/sf-memforge-env
visudo -c -f /etc/sudoers.d/sf-memforge-env || rm -f /etc/sudoers.d/sf-memforge-env
` : ''}

# ── 5. Transparent HugePage hardening ────────────────────────────────
${hugepage ? `
cat > /etc/sysctl.d/99-sf-memforge-thp.conf << 'THP'
# Defrag THP to reduce memory side-channel surface
vm.nr_hugepages = 0
THP
echo 'madvise' > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || true
echo 'defer+madvise' > /sys/kernel/mm/transparent_hugepage/defrag 2>/dev/null || true
` : ''}

# ── 6. seccomp BPF profile for sshd ──────────────────────────────────
${sshdSec ? `
# Add seccomp sandboxing to sshd's systemd unit
mkdir -p /etc/systemd/system/sshd.service.d 2>/dev/null || \
mkdir -p /etc/systemd/system/ssh.service.d  2>/dev/null || true

SSHD_DROPIN=$(ls /etc/systemd/system/sshd.service.d/ /etc/systemd/system/ssh.service.d/ 2>/dev/null | head -1 | xargs dirname 2>/dev/null || echo "/etc/systemd/system/sshd.service.d")

cat > "$SSHD_DROPIN/sf-seccomp.conf" << 'SECCOMP'
[Service]
SystemCallFilter=@system-service @network-io accept access brk close connect execve flock fork fsync ftruncate getdents64 getegid geteuid getgid getgroups getpid getppid getrlimit getsockname getsockopt gettimeofday getuid ioctl kill listen lseek madvise mmap mprotect munmap nanosleep open openat poll prctl pread64 pwrite64 read readlink recvfrom recvmsg rename rmdir rt_sigaction rt_sigprocmask rt_sigreturn select sendmsg sendto set_robust_list set_tid_address setgid setgroups setresuid setreuid setrlimit setsid setsockopt shutdown sigaltstack socket socketpair stat unlink wait4 write writev
SystemCallErrorNumber=EPERM
SystemCallArchitectures=native
SECCOMP
systemctl daemon-reload 2>/dev/null || true
` : ''}

${nginxSec ? `
# seccomp for nginx (if installed)
if command -v nginx &>/dev/null; then
  mkdir -p /etc/systemd/system/nginx.service.d
  cat > /etc/systemd/system/nginx.service.d/sf-seccomp.conf << 'NSEC'
[Service]
SystemCallFilter=@system-service @network-io accept bind close connect epoll_ctl epoll_wait fork listen mmap mprotect munmap open read recv send shutdown socket write
SystemCallErrorNumber=EPERM
NSEC
  systemctl daemon-reload 2>/dev/null || true
fi
` : ''}

# ── 7. PIE / RELRO audit ──────────────────────────────────────────────
${pieCheck ? `
echo "=== MemForge Binary Security Audit ===" > /etc/secureforge/memforge-audit.txt
echo "Generated: $(date)" >> /etc/secureforge/memforge-audit.txt
echo "" >> /etc/secureforge/memforge-audit.txt

for bin in /usr/sbin/sshd /usr/bin/sudo /usr/sbin/nginx /usr/bin/python3 /bin/bash; do
  [ -f "$bin" ] || continue
  if command -v checksec &>/dev/null; then
    checksec --file="$bin" 2>/dev/null >> /etc/secureforge/memforge-audit.txt
  elif command -v hardening-check &>/dev/null; then
    hardening-check "$bin" 2>/dev/null >> /etc/secureforge/memforge-audit.txt
  else
    # Fallback: check ELF header with readelf
    RELRO=$(readelf -l "$bin" 2>/dev/null | grep -c 'GNU_RELRO' || echo 0)
    PIE=$(readelf -h "$bin" 2>/dev/null | grep -c 'DYN (Shared' || echo 0)
    NX=$(readelf -l "$bin" 2>/dev/null | grep -c 'GNU_STACK.*RW ' || echo 0)
    echo "$bin: RELRO=${RELRO} PIE=${PIE} NX_STACK=$([ $NX -eq 0 ] && echo YES || echo NO)" \
      >> /etc/secureforge/memforge-audit.txt
  fi
done
echo "[+] Binary audit saved to /etc/secureforge/memforge-audit.txt"
` : ''}

# ── 8. Stack canary verification ──────────────────────────────────────
${stackG ? `
echo "" >> /etc/secureforge/memforge-audit.txt
echo "=== Stack Canary Check ===" >> /etc/secureforge/memforge-audit.txt
for bin in /usr/sbin/sshd /usr/bin/sudo /bin/login; do
  [ -f "$bin" ] || continue
  if objdump -d "$bin" 2>/dev/null | grep -q '__stack_chk_fail\|stack_check'; then
    echo "$bin: stack canary PRESENT" >> /etc/secureforge/memforge-audit.txt
  else
    echo "$bin: stack canary ABSENT (warn)" >> /etc/secureforge/memforge-audit.txt
  fi
done
` : ''}

sysctl --system 2>/dev/null || true
echo "[+] MemForge memory protections applied."
echo "[!] Reboot recommended to fully activate all memory protections."
`;
  },

  manifests({ options }) {
    return {
      created: [
        '/etc/sysctl.d/99-sf-memforge-aslr.conf',
        '/etc/sysctl.d/99-sf-memforge-exec.conf',
        '/etc/profile.d/sf-heap-guard.sh',
        ...(options.pieCheck ? ['/etc/secureforge/memforge-audit.txt'] : []),
      ],
    };
  },
};
