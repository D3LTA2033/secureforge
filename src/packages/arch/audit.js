export default {
  id: 'audit',
  name: 'Audit & Logging',
  description: 'auditd rules, fail2ban, rkhunter, lynis, syslog hardening',
  category: 'Monitoring',
  defaultEnabled: true,

  options: [
    { id: 'fail2ban',     type: 'confirm', label: 'Install & configure fail2ban?',                   default: true },
    { id: 'f2bBanTime',  type: 'input',   label: 'fail2ban ban duration (e.g. 24h, 7d):',            default: '24h' },
    { id: 'f2bMaxRetry', type: 'input',   label: 'fail2ban max retries before ban:',                 default: '3',
      validate: v => parseInt(v) > 0 || 'Must be > 0' },
    { id: 'lynis',        type: 'confirm', label: 'Install lynis (audit scanner)?',                   default: true },
    { id: 'rkhunter',     type: 'confirm', label: 'Install rkhunter (rootkit scanner)?',              default: true },
    { id: 'auditd',       type: 'confirm', label: 'Configure auditd with comprehensive rules?',       default: true },
    { id: 'logRotation',  type: 'confirm', label: 'Harden logrotate (compress, restrict perms)?',    default: true },
    { id: 'remoteLog',    type: 'confirm', label: 'Forward syslog to remote server?',                 default: false },
    { id: 'remoteSyslog', type: 'input',   label: 'Remote syslog host (host:port):',                  default: '',
      when: a => a.remoteLog },
  ],

  generate({ options }) {
    const f2b        = options.fail2ban    ?? true;
    const banTime    = options.f2bBanTime  ?? '24h';
    const maxRetry   = parseInt(options.f2bMaxRetry ?? '3');
    const lynis      = options.lynis       ?? true;
    const rkhunt     = options.rkhunter    ?? true;
    const auditd     = options.auditd      ?? true;
    const logRot     = options.logRotation ?? true;
    const remoteSys  = options.remoteLog   ?? false;
    const syslogHost = options.remoteSyslog ?? '';

    return `
# ── Audit & Logging (Arch) ────────────────────────────────────────────
pacman -S --noconfirm --needed \\
  ${f2b    ? 'fail2ban' : ''} \\
  ${lynis  ? 'lynis'   : ''} \\
  ${rkhunt ? 'rkhunter': ''} \\
  ${auditd ? 'audit'   : ''} \\
  2>/dev/null || true

${f2b ? `
# ── fail2ban ──────────────────────────────────────────────────────────
mkdir -p /etc/fail2ban/jail.d /etc/fail2ban/filter.d

cat > /etc/fail2ban/jail.d/secureforge.conf << 'F2B'
[DEFAULT]
bantime      = ${banTime}
findtime     = 10m
maxretry     = ${maxRetry}
backend      = systemd
banaction    = iptables-multiport

[sshd]
enabled  = true
port     = ssh
logpath  = %(sshd_log)s
maxretry = ${maxRetry}

[sshd-ddos]
enabled  = true
port     = ssh
filter   = sshd-ddos
logpath  = %(sshd_log)s
maxretry = 6
findtime = 1m
bantime  = 48h

[recidive]
enabled  = true
logpath  = /var/log/fail2ban.log
banaction = iptables-allports
bantime  = 7d
findtime = 1d
maxretry = 3
F2B

systemctl enable --now fail2ban
` : ''}

${auditd ? `
# ── auditd rules ──────────────────────────────────────────────────────
mkdir -p /etc/audit/rules.d

cat > /etc/audit/rules.d/99-secureforge.rules << 'AUDIT'
# Delete all existing rules
-D

# Buffer size
-b 8192

# Failure mode: 1=log, 2=panic
-f 1

# Identity changes
-w /etc/passwd     -p wa -k identity
-w /etc/group      -p wa -k identity
-w /etc/shadow     -p wa -k identity
-w /etc/gshadow    -p wa -k identity
-w /etc/sudoers    -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Auth / login
-w /var/log/auth.log -p wa -k auth_log
-w /var/log/faillog  -p wa -k auth_log
-w /etc/pam.d/       -p wa -k pam_config

# Network config
-w /etc/hosts          -p wa -k network
-w /etc/hostname       -p wa -k network
-w /etc/resolv.conf    -p wa -k network
-w /etc/sysconfig/network -p wa -k network
-w /etc/network/       -p wa -k network

# Kernel module loading
-w /sbin/insmod  -p x -k modules
-w /sbin/rmmod   -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# Privilege escalation
-w /bin/su         -p x -k priv_esc
-w /usr/bin/sudo   -p x -k priv_esc
-a always,exit -F arch=b64 -S setuid -S setgid -k priv_esc

# File deletion by privileged users
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

# All command execution
-a always,exit -F arch=b64 -S execve -k exec_log

# Mount operations
-a always,exit -F arch=b64 -S mount -k mount

# Cron changes
-w /etc/cron.d/      -p wa -k cron
-w /etc/crontab      -p wa -k cron
-w /var/spool/cron/  -p wa -k cron

# SSH authorized keys
-w /root/.ssh                -p wa -k ssh_keys
-a always,exit -F arch=b64 -F dir=/home -F filename=.ssh -p wa -k ssh_keys

# SecureForge own config
-w /etc/secureforge/ -p wa -k secureforge

# Make config immutable (must reboot to change audit rules)
-e 2
AUDIT

augenrules --load 2>/dev/null || systemctl restart auditd
systemctl enable auditd
` : ''}

${rkhunt ? `
# ── rkhunter ──────────────────────────────────────────────────────────
rkhunter --update 2>/dev/null || true
rkhunter --propupd 2>/dev/null || true

# Weekly scan cron
cat > /etc/cron.weekly/sf-rkhunter << 'RKH'
#!/bin/bash
/usr/bin/rkhunter --cronjob --update --quiet 2>&1 | mail -s "rkhunter weekly: $(hostname)" root 2>/dev/null || \
  /usr/bin/rkhunter --cronjob --update --quiet >> /var/log/rkhunter.log
RKH
chmod 755 /etc/cron.weekly/sf-rkhunter
` : ''}

${lynis ? `
# ── lynis ─────────────────────────────────────────────────────────────
# Monthly audit cron
cat > /etc/cron.monthly/sf-lynis << 'LYN'
#!/bin/bash
/usr/bin/lynis audit system --quiet --logfile /var/log/lynis.log --report-file /var/log/lynis-report.dat
LYN
chmod 755 /etc/cron.monthly/sf-lynis
` : ''}

${logRot ? `
# ── logrotate hardening ───────────────────────────────────────────────
cat > /etc/logrotate.d/secureforge << 'LR'
/var/log/auth.log
/var/log/syslog
/var/log/kern.log {
    weekly
    rotate 52
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate 2>/dev/null || true
    endscript
}
LR
` : ''}

${remoteSys && syslogHost ? `
# ── Remote syslog ─────────────────────────────────────────────────────
cat > /etc/rsyslog.d/50-sf-remote.conf << 'RSYS'
*.* @@${syslogHost}
RSYS
systemctl restart rsyslog 2>/dev/null || true
` : ''}
`;
  },

  manifests({ options }) {
    return {
      created: [
        ...(options.fail2ban  ? ['/etc/fail2ban/jail.d/secureforge.conf'] : []),
        ...(options.auditd    ? ['/etc/audit/rules.d/99-secureforge.rules'] : []),
        ...(options.rkhunter  ? ['/etc/cron.weekly/sf-rkhunter'] : []),
        ...(options.lynis     ? ['/etc/cron.monthly/sf-lynis'] : []),
      ],
      packages_installed: [
        ...(options.fail2ban  ? ['fail2ban'] : []),
        ...(options.lynis     ? ['lynis']    : []),
        ...(options.rkhunter  ? ['rkhunter'] : []),
        ...(options.auditd    ? ['audit']    : []),
      ],
    };
  },
};
