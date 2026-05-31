export default {
  id: 'audit',
  name: 'Audit & Logging',
  description: 'auditd, fail2ban, lynis, rkhunter via Portage + OpenRC',
  category: 'Monitoring',
  defaultEnabled: true,

  options: [
    { id: 'fail2ban',   type: 'confirm', label: 'Install fail2ban?',            default: true },
    { id: 'f2bBanTime', type: 'input',   label: 'fail2ban ban duration:',        default: '24h' },
    { id: 'f2bMaxRetry',type: 'input',   label: 'fail2ban max retries:',         default: '3' },
    { id: 'lynis',      type: 'confirm', label: 'Install lynis?',                default: true },
    { id: 'rkhunter',   type: 'confirm', label: 'Install rkhunter?',             default: true },
    { id: 'auditd',     type: 'confirm', label: 'Configure auditd?',             default: true },
  ],

  generate({ options }) {
    const f2b      = options.fail2ban    ?? true;
    const banTime  = options.f2bBanTime  ?? '24h';
    const maxRetry = parseInt(options.f2bMaxRetry ?? '3');
    const lynis    = options.lynis       ?? true;
    const rkhunt   = options.rkhunter    ?? true;
    const auditd   = options.auditd      ?? true;

    return `
# ── Audit & Logging (Gentoo) ──────────────────────────────────────────
# [ALPHA] Note: Portage compiles from source — this may take a while.
emerge --ask=n \
  ${f2b    ? 'net-analyzer/fail2ban' : ''} \
  ${lynis  ? 'app-admin/lynis'       : ''} \
  ${rkhunt ? 'app-admin/rkhunter'    : ''} \
  ${auditd ? 'sys-process/audit'     : ''}

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
rc-service fail2ban start
` : ''}

${auditd ? `
mkdir -p /etc/audit/rules.d
cat > /etc/audit/rules.d/99-secureforge.rules << 'AUDIT'
-D
-b 8192
-f 1
-w /etc/passwd  -p wa -k identity
-w /etc/shadow  -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/pam.d/  -p wa -k pam_config
-a always,exit -F arch=b64 -S execve -k exec_log
-a always,exit -F arch=b64 -S setuid -S setgid -k priv_esc
-e 2
AUDIT
rc-update add auditd default
rc-service auditd start
` : ''}

${rkhunt ? `
rkhunter --update 2>/dev/null || true
rkhunter --propupd 2>/dev/null || true
` : ''}
`;
  },

  manifests({ options }) {
    return {
      created: [
        ...(options.fail2ban ? ['/etc/fail2ban/jail.d/secureforge.conf'] : []),
        ...(options.auditd   ? ['/etc/audit/rules.d/99-secureforge.rules'] : []),
      ],
    };
  },
};
