import { pm, pkg, isOpenRC, svcEnableNow } from './pkg.js';

export default {
  id: 'canary',
  name: 'Canary Files',
  description: '[EXPERIMENTAL] Plant fake sensitive files — any access triggers an instant alert',
  category: 'Deception',
  maturity: 'experimental',
  defaultEnabled: false,

  options: [
    { id: 'canaryDir',       type: 'input',   label: 'Directory for canary files:',                    default: '/opt/.canary' },
    { id: 'fakePasswords',   type: 'confirm', label: 'Plant fake passwords.txt / credentials file?',   default: true },
    { id: 'fakeSSHKey',      type: 'confirm', label: 'Plant fake id_rsa (looks like a real SSH key)?', default: true },
    { id: 'fakeAWSCreds',    type: 'confirm', label: 'Plant fake AWS credentials file?',               default: true },
    { id: 'fakeDatabase',    type: 'confirm', label: 'Plant fake database dump (db_backup.sql)?',      default: true },
    { id: 'alertWebhook',    type: 'confirm', label: 'Alert via webhook when canary is triggered?',    default: false },
    { id: 'webhookUrl',      type: 'input',   label: 'Webhook URL:',                                   default: '',
      validate: v => !v || v.startsWith('http') || 'Must be a valid URL' },
    { id: 'alertEmail',      type: 'confirm', label: 'Alert via email (requires mailutils)?',          default: false },
    { id: 'alertEmail_addr', type: 'input',   label: 'Alert email address:',                           default: 'root' },
    { id: 'killProcess',     type: 'confirm', label: 'Kill accessing process immediately on trigger?', default: false },
    { id: 'logToSyslog',     type: 'confirm', label: 'Log canary access to syslog?',                   default: true },
  ],

  generate({ distro, options }) {
    const canaryDir   = options.canaryDir    ?? '/opt/.canary';
    const fakePass    = options.fakePasswords ?? true;
    const fakeSSH     = options.fakeSSHKey    ?? true;
    const fakeAWS     = options.fakeAWSCreds  ?? true;
    const fakeDB      = options.fakeDatabase  ?? true;
    const webhook     = options.alertWebhook  ?? false;
    const webhookUrl  = options.webhookUrl    ?? '';
    const email       = options.alertEmail    ?? false;
    const emailAddr   = options.alertEmail_addr ?? 'root';
    const killProc    = options.killProcess   ?? false;
    const logSyslog   = options.logToSyslog   ?? true;

    const useOpenRC   = isOpenRC(distro);

    return `
# ── Canary Files (${distro}) ───────────────────────────────────────────
# [EXPERIMENTAL] Any read/open/access of these files triggers an alert.
# Attackers who find them think they've struck gold — you get an instant tip-off.

${pm(distro)(pkg(distro, 'inotify') + ' curl')} 2>/dev/null || true
${email ? pm(distro)('mailutils') + ' 2>/dev/null || true' : ''}

# ── 1. Create canary directory ────────────────────────────────────────
mkdir -p '${canaryDir}'
chmod 755 '${canaryDir}'

${fakePass ? `
# Fake credentials file — looks like a real leaked password file
cat > '${canaryDir}/passwords.txt' << 'FAKEPASS'
# Company Internal Credentials - DO NOT SHARE
# Last updated: 2024-01-15

admin:P@ssw0rd!2024
root:toor123!
database_admin:DbPass#9912
vpn_user:VpnSecure@99
api_key:CANARY_FAKE_KEY_NOT_REAL_DO_NOT_USE
backup_user:B4ckup!Secure2024
FAKEPASS
chmod 644 '${canaryDir}/passwords.txt'
` : ''}

${fakeSSH ? `
# Fake RSA private key — looks syntactically valid
cat > '${canaryDir}/id_rsa' << 'FAKESSH'
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4PAtEsHAMLFCPIbMmqSPpLB5ILa
vfJ7rCxJcRZXFdBqTPnLJ2BPKVM7SQHXZ9RyVG7KWVakq/rIYMJJFVuTfnJXx8sB
GZ1k4HJrxCyqJFjX3JGKSmYjGVLQTVYFORwLLSPjrMPbK5wJAz/VQsq1LKYK3ZxJ
jz2VGMQnT8pLYYFvkBqExM4TBxNJnM4R8LhqYQ2jLPnNkGRMGnApXFr5HvzN9e3D
3mQL7pq5rJY5kNLq2OZNNq4KGFBJrWiM1VFvZe9sONLQjV5yqEZ0bFN/EXAMPLE==
-----END RSA PRIVATE KEY-----
FAKESSH
chmod 600 '${canaryDir}/id_rsa'
` : ''}

${fakeAWS ? `
# Fake AWS credentials file
cat > '${canaryDir}/.aws-credentials' << 'FAKEAWS'
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1

[production]
aws_access_key_id = AKIAI44QH8DHBEXAMPLE
aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
FAKEAWS
chmod 600 '${canaryDir}/.aws-credentials'
` : ''}

${fakeDB ? `
# Fake database dump
cat > '${canaryDir}/db_backup.sql' << 'FAKEDB'
-- MySQL dump 10.13 - Production Database Backup
-- Date: 2024-01-15 03:00:01

CREATE DATABASE IF NOT EXISTS \`prod_main\`;
USE \`prod_main\`;

CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(255) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  api_token VARCHAR(128),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users VALUES
(1,'admin@company.com','$2y$10$ExampleHashedPassword','tok_live_EXAMPLETOKEN',NOW()),
(2,'ceo@company.com','$2y$10$AnotherExampleHash','tok_live_ANOTHERTOKEN',NOW());
FAKEDB
chmod 644 '${canaryDir}/db_backup.sql'
` : ''}

# ── 2. Write canary alert script ──────────────────────────────────────
cat > /usr/local/bin/sf-canary-alert << 'ALERT'
#!/usr/bin/env bash
FILE="$1"
EVENT="$2"
PID="$3"
PROC=$(cat /proc/${PID}/comm 2>/dev/null || echo "unknown")
USER=$(cat /proc/${PID}/status 2>/dev/null | awk '/^Uid:/{print $2}' | xargs id -un 2>/dev/null || echo "unknown")
SRC_IP=$(ss -p 2>/dev/null | awk -v pid="$PID" '$0 ~ "pid="pid {match($0,/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+/); print substr($0,RSTART,RLENGTH)}' | head -1)
HOSTNAME=$(hostname)
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

MSG="[CANARY TRIGGERED] host=$HOSTNAME time=$TIMESTAMP file=$FILE event=$EVENT pid=$PID proc=$PROC user=$USER src_ip=${SRC_IP:-local}"

${logSyslog ? `logger -t secureforge-canary "$MSG"` : ''}
echo "$MSG" >> /var/log/secureforge-canary.log

${webhook && webhookUrl ? `
curl -s -X POST '${webhookUrl}' -H 'Content-Type: application/json' \
  -d "{\"event\":\"canary\",\"file\":\"$FILE\",\"user\":\"$USER\",\"pid\":$PID,\"proc\":\"$PROC\",\"src_ip\":\"$SRC_IP\",\"host\":\"$HOSTNAME\",\"time\":\"$TIMESTAMP\"}" \
  &>/dev/null &
` : ''}

${email ? `
echo "$MSG" | mail -s "[SECUREFORGE CANARY] $HOSTNAME: $FILE accessed" '${emailAddr}' 2>/dev/null &
` : ''}

${killProc ? `
# Kill the accessing process immediately
kill -9 "$PID" 2>/dev/null || true
logger -t secureforge-canary "Killed PID $PID ($PROC) for canary access"
` : ''}
ALERT
chmod 750 /usr/local/bin/sf-canary-alert
touch /var/log/secureforge-canary.log
chmod 640 /var/log/secureforge-canary.log

# ── 3. inotifywait watchdog daemon ────────────────────────────────────
cat > /usr/local/bin/sf-canary-watch << 'WATCH'
#!/usr/bin/env bash
# SecureForge Canary File Watchdog — runs as a daemon

DIR='${canaryDir}'
LOG=/var/log/secureforge-canary.log

inotifywait -m -r -e access,open,read \\
  --format '%e %w%f %T' --timefmt '%Y-%m-%d %H:%M:%S' \\
  "$DIR" 2>/dev/null | while read -r EVENT FILE TIME; do
    # Get the PID of the accessing process via /proc (best-effort)
    PID=$(lsof "$FILE" 2>/dev/null | awk 'NR>1 {print $2}' | head -1)
    PID=${PID:-0}
    /usr/local/bin/sf-canary-alert "$FILE" "$EVENT" "$PID"
done
WATCH
chmod 750 /usr/local/bin/sf-canary-watch

# ── 4. Service unit ───────────────────────────────────────────────────
${useOpenRC ? `
cat > /etc/init.d/sf-canary << 'RCSCRIPT'
#!/sbin/openrc-run
description="SecureForge Canary File Watchdog"
command=/usr/local/bin/sf-canary-watch
command_background=yes
pidfile=/run/sf-canary.pid
output_log=/var/log/secureforge-canary.log
error_log=/var/log/secureforge-canary.log

depend() {
  need net
}
RCSCRIPT
chmod 755 /etc/init.d/sf-canary
rc-update add sf-canary default
rc-service sf-canary start
` : `
cat > /etc/systemd/system/sf-canary.service << 'UNIT'
[Unit]
Description=SecureForge Canary File Watchdog
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sf-canary-watch
Restart=always
RestartSec=5
PrivateTmp=false
NoNewPrivileges=true
StandardOutput=append:/var/log/secureforge-canary.log
StandardError=append:/var/log/secureforge-canary.log

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
${svcEnableNow(distro, 'sf-canary')}
`}

echo "[+] Canary files planted in ${canaryDir}"
echo "[!] Watch /var/log/secureforge-canary.log for triggers."
echo "[!] These files are FAKE — do not mistake them for real credentials."
`;
  },

  manifests({ options }) {
    return {
      created: [
        options.canaryDir ?? '/opt/.canary',
        '/usr/local/bin/sf-canary-alert',
        '/usr/local/bin/sf-canary-watch',
        '/var/log/secureforge-canary.log',
      ],
    };
  },
};
