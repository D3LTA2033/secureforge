export default {
  id: 'audit',
  name: 'Audit & Logging',
  description: 'auditd, fail2ban, aide, lynis, rkhunter, remote syslog',
  category: 'Monitoring',
  defaultEnabled: true,

  options: [
    { id: 'fail2ban',    type: 'confirm', label: 'Install & configure fail2ban?',          default: true },
    { id: 'f2bBanTime', type: 'input',   label: 'fail2ban ban duration (e.g. 24h):',       default: '24h' },
    { id: 'f2bMaxRetry',type: 'input',   label: 'fail2ban max retries:',                   default: '3' },
    { id: 'lynis',       type: 'confirm', label: 'Install lynis?',                          default: true },
    { id: 'rkhunter',    type: 'confirm', label: 'Install rkhunter?',                       default: true },
    { id: 'aide',        type: 'confirm', label: 'Install AIDE (file integrity monitor)?',  default: false },
    { id: 'auditd',      type: 'confirm', label: 'Configure auditd?',                       default: true },
    { id: 'remoteLog',   type: 'confirm', label: 'Forward syslog to remote server?',        default: false },
    { id: 'remoteSyslog',type: 'input',   label: 'Remote syslog host:port:',                default: '' },
  ],

  generate({ options }) {
    const f2b      = options.fail2ban    ?? true;
    const banTime  = options.f2bBanTime  ?? '24h';
    const maxRetry = parseInt(options.f2bMaxRetry ?? '3');
    const lynis    = options.lynis       ?? true;
    const rkhunt   = options.rkhunter    ?? true;
    const aide     = options.aide        ?? false;
    const auditd   = options.auditd      ?? true;
    const remote   = options.remoteLog   ?? false;
    const syslogH  = options.remoteSyslog ?? '';

    return `
# ── Audit & Logging (openSUSE) ────────────────────────────────────────
zypper install -y -n \
  ${f2b    ? 'fail2ban'  : ''} \
  ${lynis  ? 'lynis'     : ''} \
  ${rkhunt ? 'rkhunter'  : ''} \
  ${aide   ? 'aide'      : ''} \
  ${auditd ? 'audit'     : ''}

${f2b ? `
mkdir -p /etc/fail2ban/jail.d
cat > /etc/fail2ban/jail.d/secureforge.conf << 'F2B'
[DEFAULT]
bantime  = ${banTime}
findtime = 10m
maxretry = ${maxRetry}
backend  = systemd
banaction = firewalld

[sshd]
enabled  = true
port     = ssh
logpath  = %(sshd_log)s
maxretry = ${maxRetry}

[recidive]
enabled  = true
logpath  = /var/log/fail2ban.log
banaction = firewalld
bantime  = 7d
findtime = 1d
maxretry = 3
F2B
systemctl enable --now fail2ban
` : ''}

${auditd ? `
mkdir -p /etc/audit/rules.d
cat > /etc/audit/rules.d/99-secureforge.rules << 'AUDIT'
-D
-b 8192
-f 1
-w /etc/passwd      -p wa -k identity
-w /etc/group       -p wa -k identity
-w /etc/shadow      -p wa -k identity
-w /etc/sudoers     -p wa -k sudoers
-w /etc/sudoers.d/  -p wa -k sudoers
-w /etc/pam.d/      -p wa -k pam_config
-w /etc/apparmor.d/ -p wa -k apparmor
-w /var/log/messages -p wa -k syslog
-w /etc/hosts       -p wa -k network
-w /etc/resolv.conf -p wa -k network
-w /sbin/insmod     -p x  -k modules
-w /sbin/rmmod      -p x  -k modules
-w /sbin/modprobe   -p x  -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-w /usr/bin/sudo    -p x  -k priv_esc
-a always,exit -F arch=b64 -S setuid -S setgid -k priv_esc
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b64 -S execve -k exec_log
-a always,exit -F arch=b64 -S mount -k mount
-w /etc/cron.d/     -p wa -k cron
-w /etc/crontab     -p wa -k cron
-w /root/.ssh       -p wa -k ssh_keys
-e 2
AUDIT
augenrules --load 2>/dev/null || systemctl restart auditd
systemctl enable auditd
` : ''}

${aide ? `
aide --init 2>/dev/null || true
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null || true
cat > /etc/cron.daily/sf-aide << 'AIDE'
#!/bin/bash
/usr/sbin/aide --check >> /var/log/aide.log 2>&1
AIDE
chmod 755 /etc/cron.daily/sf-aide
` : ''}

${rkhunt ? `
rkhunter --update 2>/dev/null || true
rkhunter --propupd 2>/dev/null || true
cat > /etc/cron.weekly/sf-rkhunter << 'RKH'
#!/bin/bash
/usr/bin/rkhunter --cronjob --update --quiet >> /var/log/rkhunter.log 2>&1
RKH
chmod 755 /etc/cron.weekly/sf-rkhunter
` : ''}

${lynis ? `
cat > /etc/cron.monthly/sf-lynis << 'LYN'
#!/bin/bash
/usr/bin/lynis audit system --quiet --logfile /var/log/lynis.log
LYN
chmod 755 /etc/cron.monthly/sf-lynis
` : ''}

${remote && syslogH ? `
zypper install -y -n rsyslog
cat > /etc/rsyslog.d/50-sf-remote.conf << 'RSYS'
*.* @@${syslogH}
RSYS
systemctl restart rsyslog
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
        ...(options.aide      ? ['/etc/cron.daily/sf-aide'] : []),
      ],
      packages_installed: [
        ...(options.fail2ban  ? ['fail2ban'] : []),
        ...(options.lynis     ? ['lynis']    : []),
        ...(options.rkhunter  ? ['rkhunter'] : []),
        ...(options.aide      ? ['aide']     : []),
        ...(options.auditd    ? ['audit']    : []),
      ],
    };
  },
};
