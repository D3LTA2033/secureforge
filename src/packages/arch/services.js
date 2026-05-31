export default {
  id: 'services',
  name: 'Service Hardening',
  description: 'Disable unnecessary services, harden systemd, restrict cron',
  category: 'Services',
  defaultEnabled: true,

  options: [
    { id: 'disableAvahi',    type: 'confirm', label: 'Disable Avahi (mDNS)?',                default: true },
    { id: 'disableCups',     type: 'confirm', label: 'Disable CUPS (printing)?',             default: true },
    { id: 'disableBt',       type: 'confirm', label: 'Disable Bluetooth service?',           default: true },
    { id: 'disableNfs',      type: 'confirm', label: 'Disable NFS server?',                  default: true },
    { id: 'disableTelnet',   type: 'confirm', label: 'Remove/disable telnet?',               default: true },
    { id: 'disableFtp',      type: 'confirm', label: 'Remove vsftpd / proftpd?',             default: true },
    { id: 'disableRpc',      type: 'confirm', label: 'Disable RPC services?',                default: true },
    { id: 'systemdHarden',   type: 'confirm', label: 'Harden systemd (restrict unit capabilities)?', default: true },
    { id: 'restrictCron',    type: 'confirm', label: 'Restrict cron to root only?',          default: false },
    { id: 'disableSysRq',    type: 'confirm', label: 'Disable Magic SysRq key?',             default: true },
  ],

  generate({ options }) {
    const disableList = [];

    if (options.disableAvahi)  disableList.push('avahi-daemon');
    if (options.disableCups)   disableList.push('cups');
    if (options.disableBt)     disableList.push('bluetooth');
    if (options.disableNfs)    disableList.push('nfs-server', 'rpcbind');
    if (options.disableRpc)    disableList.push('rpcbind', 'rpc-statd');

    const sysHarden    = options.systemdHarden ?? true;
    const restrictCron = options.restrictCron  ?? false;
    const noSysRq      = options.disableSysRq  ?? true;

    return `
# ── Service Hardening (Arch) ──────────────────────────────────────────

# Disable unnecessary services
${disableList.map(svc => `
if systemctl list-unit-files | grep -q '${svc}'; then
  systemctl disable --now ${svc} 2>/dev/null && echo "[+] Disabled: ${svc}" || true
fi
`).join('')}

${options.disableTelnet ? `
pacman -R --noconfirm inetutils telnet 2>/dev/null || true
` : ''}

${options.disableFtp ? `
pacman -R --noconfirm vsftpd proftpd 2>/dev/null || true
` : ''}

${noSysRq ? `
# Disable Magic SysRq
echo 0 > /proc/sys/kernel/sysrq
echo 'kernel.sysrq = 0' > /etc/sysctl.d/99-sf-sysrq.conf
` : ''}

${sysHarden ? `
# Systemd service hardening: drop-in for sshd
mkdir -p /etc/systemd/system/sshd.service.d
cat > /etc/systemd/system/sshd.service.d/sf-harden.conf << 'SSD'
[Service]
PrivateTmp=true
PrivateDevices=true
ProtectHome=read-only
ProtectSystem=strict
NoNewPrivileges=true
ReadWritePaths=/var/run/sshd /etc/ssh
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_CHOWN CAP_DAC_READ_SEARCH CAP_FSETID CAP_KILL CAP_SETGID CAP_SETUID CAP_SETPCAP CAP_SYS_CHROOT CAP_SYS_TTY_CONFIG CAP_AUDIT_WRITE CAP_AUDIT_CONTROL
SSD

# Harden systemd-logind
mkdir -p /etc/systemd/logind.conf.d
cat > /etc/systemd/logind.conf.d/sf-harden.conf << 'LOGIND'
[Login]
KillUserProcesses=yes
KillExcludeUsers=root
RemoveIPC=yes
LOGIND

systemctl daemon-reload
systemctl restart sshd 2>/dev/null || true
` : ''}

${restrictCron ? `
# Restrict cron to root only
echo '' > /etc/cron.allow 2>/dev/null || true
echo 'root' > /etc/cron.allow
chmod 600 /etc/cron.allow
# Deny all others
echo 'ALL' > /etc/cron.deny 2>/dev/null && chmod 600 /etc/cron.deny || true
` : ''}

# Ensure services that should be running are
systemctl enable --now systemd-journald 2>/dev/null || true
`;
  },

  manifests({ options }) {
    const disableList = [];
    if (options.disableAvahi) disableList.push('avahi-daemon');
    if (options.disableCups)  disableList.push('cups');
    if (options.disableBt)    disableList.push('bluetooth');

    return {
      disabled_services: disableList,
      created: [
        ...(options.systemdHarden ? ['/etc/systemd/system/sshd.service.d/sf-harden.conf'] : []),
      ],
    };
  },
};
