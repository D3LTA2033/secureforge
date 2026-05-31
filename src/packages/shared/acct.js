import { pm, pkg } from './pkg.js';

export default {
  id: 'acct',
  name: 'Process Accounting',
  description: 'Log every executed command per user: psacct/acct + lastcomm + sa reporting',
  category: 'Monitoring',
  defaultEnabled: true,

  options: [
    { id: 'acctLog',     type: 'confirm', label: 'Enable kernel process accounting?',                     default: true },
    { id: 'saReport',    type: 'confirm', label: 'Daily sa (system accounting) summary report via cron?', default: true },
    { id: 'watchUsers',  type: 'input',   label: 'Alert if these users execute commands (space-separated, blank=all):', default: '' },
    { id: 'logHistory',  type: 'confirm', label: 'Store extended command history in /etc/secureforge/cmd-history.log?', default: true },
    { id: 'shellHistory',type: 'confirm', label: 'Harden shell history (HISTFILESIZE, HISTTIMEFORMAT, append-only)?', default: true },
  ],

  generate({ distro, options }) {
    const acctLog     = options.acctLog     ?? true;
    const saReport    = options.saReport    ?? true;
    const watchUsers  = (options.watchUsers ?? '').trim().split(/\s+/).filter(Boolean);
    const logHistory  = options.logHistory  ?? true;
    const shellHist   = options.shellHistory ?? true;

    const acctPkg = pkg(distro, 'acct');

    return `
# ── Process Accounting (${distro}) ────────────────────────────────────
${pm(distro)(acctPkg)}

${acctLog ? `
# Enable kernel-level process accounting
touch /var/log/pacct 2>/dev/null || touch /var/account/pacct 2>/dev/null || true
accton /var/log/pacct 2>/dev/null || accton /var/account/pacct 2>/dev/null || true

# Persist across reboots (distro-specific)
${distro === 'arch' ? `
cat > /etc/systemd/system/sf-acct.service << 'ACCTUNIT'
[Unit]
Description=SecureForge Process Accounting
After=sysinit.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/accton /var/log/pacct
ExecStop=/usr/sbin/accton

[Install]
WantedBy=multi-user.target
ACCTUNIT
systemctl enable --now sf-acct
` : `
systemctl enable --now psacct 2>/dev/null || \
systemctl enable --now acct   2>/dev/null || \
accton /var/log/pacct          2>/dev/null || true
`}
` : ''}

${saReport ? `
cat > /etc/cron.daily/sf-acct-report << 'SAREP'
#!/bin/bash
echo "=== System Accounting Report: $(date) ===" >> /var/log/sa/sf-daily.log
sa -a 2>/dev/null >> /var/log/sa/sf-daily.log
lastcomm 2>/dev/null | head -50 >> /var/log/sa/sf-daily.log
SAREP
chmod 755 /etc/cron.daily/sf-acct-report
mkdir -p /var/log/sa
` : ''}

${logHistory && watchUsers.length > 0 ? `
# Alert when specific users execute commands
cat > /etc/cron.hourly/sf-watch-users << 'WATCH'
#!/bin/bash
${watchUsers.map(u => `
lastcomm --user ${u} 2>/dev/null | head -20 | while read -r line; do
  logger -t secureforge-acct "USER_CMD [${u}]: $line"
done
`).join('')}
WATCH
chmod 755 /etc/cron.hourly/sf-watch-users
` : ''}

${shellHist ? `
# Harden shell history for all users
cat > /etc/profile.d/sf-history.sh << 'HIST'
# SecureForge: hardened shell history
HISTSIZE=10000
HISTFILESIZE=20000
HISTTIMEFORMAT="%Y-%m-%d %H:%M:%S  "
HISTCONTROL=ignoredups

# Append-only (don't overwrite on exit)
shopt -s histappend 2>/dev/null || true

# Record to syslog (audit every command)
PROMPT_COMMAND='history 1 | logger -t sf-shell-cmd -p local6.info'

export HISTSIZE HISTFILESIZE HISTTIMEFORMAT HISTCONTROL PROMPT_COMMAND
HIST
chmod 644 /etc/profile.d/sf-history.sh
` : ''}

${logHistory ? `
# Extended command logging via PAM pam_exec
cat > /usr/local/bin/sf-cmd-log << 'CMDLOG'
#!/bin/bash
[ -n "$PAM_USER" ] && logger -t secureforge-pam "LOGIN: user=$PAM_USER type=$PAM_TYPE rhost=${PAM_RHOST:-local}" || true
CMDLOG
chmod 750 /usr/local/bin/sf-cmd-log

# Inject into PAM session for login tracking
SESS=/etc/pam.d/common-session 2>/dev/null || SESS=/etc/pam.d/system-auth
grep -q 'sf-cmd-log' "$SESS" 2>/dev/null || \
  echo 'session optional pam_exec.so /usr/local/bin/sf-cmd-log' >> "$SESS" || true
` : ''}

echo "[+] Process accounting active. Use 'lastcomm' to view recent commands."
echo "[+] Use 'sa -a' for command frequency stats."
`;
  },

  manifests({ options }) {
    return {
      created: [
        '/etc/profile.d/sf-history.sh',
        '/etc/cron.daily/sf-acct-report',
        '/usr/local/bin/sf-cmd-log',
      ],
      packages_installed: ['acct'],
    };
  },
};
