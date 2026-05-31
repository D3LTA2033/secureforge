export default {
  id: 'audit',
  name: 'Audit & Logging',
  description: 'fail2ban, lynis, rkhunter, syslog-ng hardening (Alpine OpenRC)',
  category: 'Monitoring',
  defaultEnabled: true,

  options: [
    { id: 'fail2ban',    type: 'confirm', label: 'Install fail2ban?',         default: true },
    { id: 'f2bBanTime', type: 'input',   label: 'fail2ban ban duration:',     default: '24h' },
    { id: 'f2bMaxRetry',type: 'input',   label: 'fail2ban max retries:',      default: '3' },
    { id: 'lynis',       type: 'confirm', label: 'Install lynis?',             default: true },
    { id: 'rkhunter',    type: 'confirm', label: 'Install rkhunter?',          default: true },
    { id: 'syslogHarden',type: 'confirm', label: 'Harden syslog-ng/busybox syslog?', default: true },
    { id: 'logrotate',   type: 'confirm', label: 'Configure logrotate?',       default: true },
  ],

  generate({ options }) {
    const f2b       = options.fail2ban     ?? true;
    const banTime   = options.f2bBanTime   ?? '24h';
    const maxRetry  = parseInt(options.f2bMaxRetry ?? '3');
    const lynis     = options.lynis        ?? true;
    const rkhunt    = options.rkhunter     ?? true;
    const syslogH   = options.syslogHarden ?? true;
    const logRot    = options.logrotate    ?? true;

    return `
# ── Audit & Logging (Alpine) ──────────────────────────────────────────
# [ALPHA]
apk add --no-cache \
  ${f2b    ? 'fail2ban'         : ''} \
  ${lynis  ? 'lynis'            : ''} \
  ${rkhunt ? 'rkhunter'         : ''} \
  ${logRot ? 'logrotate'        : ''} \
  ${syslogH ? 'syslog-ng'       : ''} 2>/dev/null || true

${f2b ? `
mkdir -p /etc/fail2ban/jail.d
cat > /etc/fail2ban/jail.d/secureforge.conf << 'F2B'
[DEFAULT]
bantime  = ${banTime}
findtime = 10m
maxretry = ${maxRetry}
backend  = auto

[sshd]
enabled  = true
port     = ssh
logpath  = /var/log/messages
maxretry = ${maxRetry}
F2B
rc-update add fail2ban default
rc-service fail2ban start 2>/dev/null || true
` : ''}

${syslogH ? `
# Harden syslog — Alpine uses syslog-ng or busybox syslog
if rc-service syslog-ng status &>/dev/null || which syslog-ng &>/dev/null; then
  cat >> /etc/syslog-ng/syslog-ng.conf << 'SYSCONF'
# SecureForge: log auth separately
filter f_auth { facility(auth, authpriv); };
destination d_auth { file("/var/log/auth.log"); };
log { source(s_src); filter(f_auth); destination(d_auth); };
SYSCONF
  rc-service syslog-ng restart 2>/dev/null || true
else
  # BusyBox syslogd — log to file
  rc-update add syslog default 2>/dev/null || true
fi
` : ''}

${rkhunt ? `
rkhunter --update 2>/dev/null || true
rkhunter --propupd 2>/dev/null || true
` : ''}

${lynis ? `
cat > /etc/periodic/monthly/sf-lynis << 'LYN'
#!/bin/sh
/usr/bin/lynis audit system --quiet --logfile /var/log/lynis.log
LYN
chmod 755 /etc/periodic/monthly/sf-lynis
` : ''}
`;
  },

  manifests({ options }) {
    return {
      created: [
        ...(options.fail2ban ? ['/etc/fail2ban/jail.d/secureforge.conf'] : []),
        ...(options.lynis    ? ['/etc/periodic/monthly/sf-lynis'] : []),
      ],
    };
  },
};
