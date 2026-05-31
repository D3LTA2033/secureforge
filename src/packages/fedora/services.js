export default {
  id: 'services',
  name: 'Service Hardening',
  description: 'Disable risky services, harden systemd units, restrict cron, SELinux booleans',
  category: 'Services',
  defaultEnabled: true,

  options: [
    { id: 'disableAvahi',    type: 'confirm', label: 'Disable Avahi (mDNS)?',              default: true },
    { id: 'disableCups',     type: 'confirm', label: 'Disable CUPS (printing)?',            default: true },
    { id: 'disableBt',       type: 'confirm', label: 'Disable Bluetooth?',                  default: true },
    { id: 'disableNfs',      type: 'confirm', label: 'Disable NFS server?',                 default: true },
    { id: 'removeTelnet',    type: 'confirm', label: 'Remove telnet/rsh tools?',            default: true },
    { id: 'disableRpc',      type: 'confirm', label: 'Disable RPC services?',               default: true },
    { id: 'systemdHarden',   type: 'confirm', label: 'Harden sshd systemd unit?',           default: true },
    { id: 'restrictCron',    type: 'confirm', label: 'Restrict cron to root only?',         default: false },
    { id: 'selinuxBooleans', type: 'confirm', label: 'Apply recommended SELinux booleans?', default: true },
    { id: 'disableCoredump', type: 'confirm', label: 'Disable coredumps?',                  default: true },
  ],

  generate({ options }) {
    const disableList = [];
    if (options.disableAvahi)  disableList.push('avahi-daemon');
    if (options.disableCups)   disableList.push('cups');
    if (options.disableBt)     disableList.push('bluetooth');
    if (options.disableNfs)    disableList.push('nfs-server');
    if (options.disableRpc)    disableList.push('rpcbind', 'rpc-statd');

    const systemdHarden  = options.systemdHarden   ?? true;
    const restrictCron   = options.restrictCron    ?? false;
    const selinuxBool    = options.selinuxBooleans ?? true;
    const noCoreDump     = options.disableCoredump ?? true;

    return `
# ── Service Hardening (Fedora) ────────────────────────────────────────

${disableList.map(svc => `
systemctl disable --now ${svc} 2>/dev/null || true
`).join('')}

${options.removeTelnet ? `
dnf remove -y telnet rsh 2>/dev/null || true
` : ''}

${noCoreDump ? `
mkdir -p /etc/systemd/coredump.conf.d
cat > /etc/systemd/coredump.conf.d/sf-disable.conf << 'CORE'
[Coredump]
Storage=none
ProcessSizeMax=0
CORE
` : ''}

${systemdHarden ? `
mkdir -p /etc/systemd/system/sshd.service.d
cat > /etc/systemd/system/sshd.service.d/sf-harden.conf << 'SSD'
[Service]
PrivateTmp=true
PrivateDevices=true
ProtectHome=read-only
ProtectSystem=strict
NoNewPrivileges=true
ReadWritePaths=/var/run/sshd /etc/ssh /var/log
SSD

mkdir -p /etc/systemd/logind.conf.d
cat > /etc/systemd/logind.conf.d/sf-harden.conf << 'LOGIND'
[Login]
KillUserProcesses=yes
RemoveIPC=yes
LOGIND

systemctl daemon-reload
systemctl restart sshd 2>/dev/null || true
` : ''}

${selinuxBool ? `
# Recommended SELinux booleans
setsebool -P deny_ptrace on             2>/dev/null || true
setsebool -P secure_mode on             2>/dev/null || true
setsebool -P ftp_home_dir off           2>/dev/null || true
setsebool -P ssh_sysadm_login off       2>/dev/null || true
setsebool -P xserver_clients_write_xshm off 2>/dev/null || true
` : ''}

${restrictCron ? `
echo 'root' > /etc/cron.allow
chmod 600 /etc/cron.allow
echo 'ALL' > /etc/cron.deny && chmod 600 /etc/cron.deny || true
` : ''}

echo 'kernel.sysrq = 0' > /etc/sysctl.d/99-sf-sysrq.conf
echo 0 > /proc/sys/kernel/sysrq 2>/dev/null || true
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
        ...(options.systemdHarden   ? ['/etc/systemd/system/sshd.service.d/sf-harden.conf'] : []),
        ...(options.disableCoredump ? ['/etc/systemd/coredump.conf.d/sf-disable.conf']     : []),
      ],
    };
  },
};
