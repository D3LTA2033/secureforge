export default {
  id: 'audit',
  name: 'Audit & Logging',
  description: 'auditd, fail2ban, rkhunter, lynis, syslog hardening',
  category: 'Monitoring',
  defaultEnabled: true,

  options: [
    { id: 'fail2ban',     type: 'confirm', label: 'Install & configure fail2ban?',                   default: true },
    { id: 'f2bBanTime',  type: 'input',   label: 'fail2ban ban duration (e.g. 24h):',                default: '24h' },
    { id: 'f2bMaxRetry', type: 'input',   label: 'fail2ban max retries:',                            default: '3' },
    { id: 'lynis',        type: 'confirm', label: 'Install lynis?',                                   default: true },
    { id: 'rkhunter',     type: 'confirm', label: 'Install rkhunter?',                                default: true },
    { id: 'auditd',       type: 'confirm', label: 'Configure auditd?',                                default: true },
    { id: 'clamav',       type: 'confirm', label: 'Install ClamAV (antivirus)?',                      default: false },
    { id: 'remoteLog',    type: 'confirm', label: 'Forward syslog to remote server?',                 default: false },
    { id: 'remoteSyslog', type: 'input',   label: 'Remote syslog host:port:',                         default: '' },
  ],

  generate({ options }) {
    const f2b      = options.fail2ban    ?? true;
    const banTime  = options.f2bBanTime  ?? '24h';
    const maxRetry = parseInt(options.f2bMaxRetry ?? '3');
    const lynis    = options.lynis       ?? true;
    const rkhunt   = options.rkhunter    ?? true;
    const auditd   = options.auditd      ?? true;
    const clamav   = options.clamav      ?? false;
    const remote   = options.remoteLog   ?? false;
    const syslogH  = options.remoteSyslog ?? '';

    return `
# ── Audit & Logging (Debian) ──────────────────────────────────────────
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq \
  ${f2b    ? 'fail2ban'         : ''} \
  ${lynis  ? 'lynis'            : ''} \
  ${rkhunt ? 'rkhunter'         : ''} \
  ${auditd ? 'auditd audispd-plugins' : ''} \
  ${clamav ? 'clamav clamav-daemon' : ''}

${f2b ? `
mkdir -p /etc/fail2ban/jail.d
cat > /etc/fail2ban/jail.d/secureforge.conf << 'F2B'
[DEFAULT]
bantime  = ${banTime}
findtime = 10m
maxretry = ${maxRetry}
backend  = systemd

[sshd]
enabled  = true
port     = ssh
logpath  = %(sshd_log)s
maxretry = ${maxRetry}

[recidive]
enabled  = true
logpath  = /var/log/fail2ban.log
banaction= iptables-allports
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
-w /etc/passwd  -p wa -k identity
-w /etc/group   -p wa -k identity
-w /etc/shadow  -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /etc/pam.d/  -p wa -k pam_config
-w /var/log/auth.log -p wa -k auth_log
-w /etc/hosts   -p wa -k network
-w /etc/resolv.conf -p wa -k network
-w /sbin/insmod  -p x -k modules
-w /sbin/rmmod   -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-w /bin/su       -p x -k priv_esc
-w /usr/bin/sudo -p x -k priv_esc
-a always,exit -F arch=b64 -S setuid -S setgid -k priv_esc
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b64 -S execve -k exec_log
-a always,exit -F arch=b64 -S mount -k mount
-w /etc/cron.d/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /root/.ssh   -p wa -k ssh_keys
-a always,exit -F arch=b64 -F dir=/home -F filename=.ssh -p wa -k ssh_keys
-e 2
AUDIT
augenrules --load 2>/dev/null || service auditd restart
systemctl enable auditd
` : ''}

${clamav ? `
systemctl enable --now clamav-freshclam
freshclam --quiet 2>/dev/null || true
# Weekly scan cron
cat > /etc/cron.weekly/sf-clamav << 'CLAM'
#!/bin/bash
clamscan -r /home /tmp /var/www 2>&1 | grep -E 'FOUND|ERROR' | mail -s "ClamAV: $(hostname)" root 2>/dev/null || true
CLAM
chmod 755 /etc/cron.weekly/sf-clamav
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
apt-get install -y -qq rsyslog
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
      ],
      packages_installed: [
        ...(options.fail2ban  ? ['fail2ban'] : []),
        ...(options.lynis     ? ['lynis']    : []),
        ...(options.rkhunter  ? ['rkhunter'] : []),
        ...(options.auditd    ? ['auditd']   : []),
        ...(options.clamav    ? ['clamav']   : []),
      ],
    };
  },
};
