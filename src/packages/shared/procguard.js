import { isOpenRC, svcEnableNow } from './pkg.js';

export default {
  id: 'procguard',
  name: 'ProcGuard — Process Watchdog',
  description: '[BETA] Monitor critical services — auto-restart on crash + instant alert',
  category: 'Monitoring',
  maturity: 'beta',
  defaultEnabled: false,

  options: [
    { id: 'watchSSHD',      type: 'confirm', label: 'Watch: sshd?',                                  default: true },
    { id: 'watchNginx',     type: 'confirm', label: 'Watch: nginx?',                                  default: false },
    { id: 'watchApache',    type: 'confirm', label: 'Watch: apache2 / httpd?',                        default: false },
    { id: 'watchPostgres',  type: 'confirm', label: 'Watch: postgresql?',                             default: false },
    { id: 'watchMysql',     type: 'confirm', label: 'Watch: mysql / mariadb?',                        default: false },
    { id: 'watchFail2ban',  type: 'confirm', label: 'Watch: fail2ban?',                               default: true },
    { id: 'customProcs',    type: 'input',   label: 'Custom process names to watch (space-separated):', default: '' },
    { id: 'checkInterval',  type: 'input',   label: 'Check interval (seconds):',                      default: '30',
      validate: v => parseInt(v) >= 5 || 'Min 5 seconds' },
    { id: 'maxRestarts',    type: 'input',   label: 'Max auto-restarts before alerting without restart:', default: '5' },
    { id: 'alertWebhook',   type: 'confirm', label: 'Alert via webhook on process death?',             default: false },
    { id: 'webhookUrl',     type: 'input',   label: 'Webhook URL:',                                    default: '' },
    { id: 'logToSyslog',    type: 'confirm', label: 'Log process events to syslog?',                   default: true },
  ],

  generate({ distro, options }) {
    const watchSSHD     = options.watchSSHD     ?? true;
    const watchNginx    = options.watchNginx    ?? false;
    const watchApache   = options.watchApache   ?? false;
    const watchPostgres = options.watchPostgres ?? false;
    const watchMysql    = options.watchMysql    ?? false;
    const watchFail2ban = options.watchFail2ban ?? true;
    const customProcs   = (options.customProcs ?? '').trim().split(/\s+/).filter(Boolean);
    const interval      = parseInt(options.checkInterval ?? '30');
    const maxRestarts   = parseInt(options.maxRestarts   ?? '5');
    const webhook       = options.alertWebhook  ?? false;
    const webhookUrl    = options.webhookUrl    ?? '';
    const logSyslog     = options.logToSyslog   ?? true;

    const useOpenRC = isOpenRC(distro);

    // Build watch list
    const procMap = {
      sshd:    { proc: 'sshd',      svc: useOpenRC ? 'sshd'   : 'sshd',    watch: watchSSHD },
      nginx:   { proc: 'nginx',     svc: useOpenRC ? 'nginx'  : 'nginx',   watch: watchNginx },
      apache:  { proc: 'apache2',   svc: useOpenRC ? 'apache2': 'apache2', watch: watchApache },
      pg:      { proc: 'postgres',  svc: useOpenRC ? 'postgresql' : 'postgresql', watch: watchPostgres },
      mysql:   { proc: 'mysqld',    svc: useOpenRC ? 'mysql'  : 'mysql',   watch: watchMysql },
      fail2ban:{ proc: 'fail2ban-server', svc: useOpenRC ? 'fail2ban' : 'fail2ban', watch: watchFail2ban },
    };

    const watchList = Object.values(procMap)
      .filter(p => p.watch)
      .map(p => `"${p.proc}|${p.svc}"`)
      .concat(customProcs.map(p => `"${p}|${p}"`));

    const svcRestartCmd = useOpenRC
      ? 'rc-service "$SVC_NAME" restart 2>/dev/null'
      : 'systemctl restart "$SVC_NAME" 2>/dev/null';

    return `
# ── ProcGuard: Process Watchdog (${distro}) ───────────────────────────
# [BETA] Monitors critical processes and auto-restarts them on failure.

# ── Write watchdog script ─────────────────────────────────────────────
cat > /usr/local/bin/sf-procguard << 'WATCHDOG'
#!/usr/bin/env bash
# SecureForge ProcGuard — Process Watchdog Daemon

INTERVAL=${interval}
MAX_RESTARTS=${maxRestarts}
RESTART_COUNTS_FILE=/var/run/sf-procguard-counts
LOG=/var/log/sf-procguard.log

declare -A RESTART_COUNTS

alert() {
  local MSG="$1"
  ${logSyslog ? `logger -t sf-procguard "$MSG"` : ''}
  echo "$(date '+%Y-%m-%d %H:%M:%S') $MSG" >> "$LOG"
  ${webhook && webhookUrl ? `
  curl -s -X POST '${webhookUrl}' -H 'Content-Type: application/json' \
    -d "{\"event\":\"procguard\",\"message\":\"$MSG\",\"host\":\"$(hostname)\"}" \
    &>/dev/null &
  ` : ''}
}

# Process list: "proc_name|service_name"
WATCH_LIST=(
  ${watchList.join('\n  ')}
)

alert "ProcGuard started. Watching ${watchList.length} process(es)."

while true; do
  for ENTRY in "\${WATCH_LIST[@]}"; do
    PROC_NAME="\${ENTRY%%|*}"
    SVC_NAME="\${ENTRY##*|}"
    COUNT_KEY="${PROC_NAME}"

    if ! pgrep -x "$PROC_NAME" &>/dev/null; then
      RESTARTS="\${RESTART_COUNTS[$COUNT_KEY]:-0}"

      if [[ $RESTARTS -lt ${maxRestarts} ]]; then
        alert "PROCESS DOWN: $PROC_NAME — attempting restart ($((RESTARTS+1))/${maxRestarts})"
        ${useOpenRC ? `rc-service "$SVC_NAME" restart 2>/dev/null` : `systemctl restart "$SVC_NAME" 2>/dev/null`} && \
          alert "RESTARTED: $SVC_NAME OK" || \
          alert "RESTART FAILED: $SVC_NAME"
        RESTART_COUNTS[$COUNT_KEY]=$((RESTARTS + 1))
      else
        alert "CRITICAL: $PROC_NAME down, max restarts (${maxRestarts}) reached — manual intervention required"
      fi
    else
      # Process running — reset counter
      RESTART_COUNTS[$COUNT_KEY]=0
    fi
  done

  sleep $INTERVAL
done
WATCHDOG

chmod 750 /usr/local/bin/sf-procguard
touch /var/log/sf-procguard.log
chmod 640 /var/log/sf-procguard.log

# ── Service unit ──────────────────────────────────────────────────────
${useOpenRC ? `
cat > /etc/init.d/sf-procguard << 'RCSCRIPT'
#!/sbin/openrc-run
description="SecureForge ProcGuard Watchdog"
command=/usr/local/bin/sf-procguard
command_background=yes
pidfile=/run/sf-procguard.pid
output_log=/var/log/sf-procguard.log
error_log=/var/log/sf-procguard.log

depend() {
  need net
}
RCSCRIPT
chmod 755 /etc/init.d/sf-procguard
rc-update add sf-procguard default
rc-service sf-procguard start
` : `
cat > /etc/systemd/system/sf-procguard.service << 'UNIT'
[Unit]
Description=SecureForge ProcGuard Process Watchdog
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sf-procguard
Restart=always
RestartSec=10
StandardOutput=append:/var/log/sf-procguard.log
StandardError=append:/var/log/sf-procguard.log
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
${svcEnableNow(distro, 'sf-procguard')}
`}

echo "[+] ProcGuard watching: ${watchList.map(p => p.replace(/"|\|.*/g, '')).join(', ')}"
echo "[!] Log: /var/log/sf-procguard.log"
`;
  },

  manifests() {
    return {
      created: [
        '/usr/local/bin/sf-procguard',
        '/var/log/sf-procguard.log',
        '/etc/systemd/system/sf-procguard.service',
      ],
    };
  },
};
