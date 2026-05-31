import { pm, isOpenRC, svcEnableNow } from './pkg.js';

export default {
  id: 'tarpit',
  name: 'SSH Tarpit (endlessh)',
  description: '[EXPERIMENTAL] Bog down SSH scanners on port 22 indefinitely — real SSH moves to custom port',
  category: 'Deception',
  maturity: 'experimental',
  defaultEnabled: false,

  options: [
    { id: 'tarpitPort',  type: 'input',   label: 'Port for the tarpit (attackers connect here, usually 22):',  default: '22',
      validate: v => (parseInt(v) > 0 && parseInt(v) < 65535) || 'Invalid port' },
    { id: 'realSshPort', type: 'input',   label: 'Move REAL SSH daemon to this port:',                         default: '2222',
      validate: v => (parseInt(v) > 1024 && parseInt(v) < 65535) || 'Use port 1025–65534' },
    { id: 'maxClients',  type: 'input',   label: 'Max simultaneous tarpit connections:',                        default: '4096' },
    { id: 'lineLen',     type: 'input',   label: 'SSH banner line length (bytes — longer = slower handshake):', default: '32' },
    { id: 'delay',       type: 'input',   label: 'Milliseconds between banner lines (lower = more torment):',   default: '10000' },
    { id: 'logTarpit',   type: 'confirm', label: 'Log tarpit connections to syslog?',                           default: true },
    { id: 'banAfter',    type: 'confirm', label: 'Auto-ban IPs after N tarpit hits via fail2ban?',              default: true },
    { id: 'banHits',     type: 'input',   label: 'Ban after N connection attempts:',                            default: '3' },
  ],

  generate({ distro, options }) {
    const tarpitPort = parseInt(options.tarpitPort  ?? '22');
    const realPort   = parseInt(options.realSshPort ?? '2222');
    const maxClients = parseInt(options.maxClients  ?? '4096');
    const lineLen    = parseInt(options.lineLen     ?? '32');
    const delay      = parseInt(options.delay       ?? '10000');
    const logIt     = options.logTarpit  ?? true;
    const banAfter  = options.banAfter   ?? true;
    const banHits   = parseInt(options.banHits ?? '3');

    const useOpenRC = isOpenRC(distro);

    return `
# ── SSH Tarpit: endlessh (${distro}) ─────────────────────────────────
# [EXPERIMENTAL] endlessh traps SSH scanners in an infinite handshake.
# Real SSH is moved to port ${realPort}. Attackers waste resources on port ${tarpitPort}.

# ── 1. Install build dependencies ────────────────────────────────────
${pm(distro)('git gcc make')} 2>/dev/null || true

# ── 2. Compile endlessh from source ──────────────────────────────────
ENDLESSH_SRC=$(mktemp -d /tmp/endlessh.XXXXXX)
git clone --depth=1 https://github.com/skeeto/endlessh "$ENDLESSH_SRC" 2>/dev/null || {
  echo "[!] git clone failed — check internet connection."
  exit 1
}
cd "$ENDLESSH_SRC"
make
cp endlessh /usr/local/sbin/endlessh
chmod 755 /usr/local/sbin/endlessh
cd / && rm -rf "$ENDLESSH_SRC"
echo "[+] endlessh compiled and installed."

# ── 3. Config ────────────────────────────────────────────────────────
mkdir -p /etc/endlessh
cat > /etc/endlessh/config << 'ECFG'
Port ${tarpitPort}
MaxLineLength ${lineLen}
MaxClients ${maxClients}
LogLevel ${logIt ? '1' : '0'}
BindFamily 0
Delay ${delay}
ECFG
chmod 600 /etc/endlessh/config

# ── 4. Service setup ──────────────────────────────────────────────────
${useOpenRC ? `
# OpenRC service for endlessh
cat > /etc/init.d/endlessh << 'RCSCRIPT'
#!/sbin/openrc-run
description="endlessh SSH Tarpit"
command=/usr/local/sbin/endlessh
command_args="-c /etc/endlessh/config"
command_background=yes
pidfile=/run/endlessh.pid

depend() {
  need net
  after firewall
}
RCSCRIPT
chmod 755 /etc/init.d/endlessh
rc-update add endlessh default
rc-service endlessh start
` : `
# systemd unit for endlessh
cat > /etc/systemd/system/endlessh.service << 'SVCEOF'
[Unit]
Description=endlessh SSH Tarpit
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/endlessh -c /etc/endlessh/config
Restart=on-failure
RestartSec=5
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
SVCEOF
systemctl daemon-reload
${svcEnableNow(distro, 'endlessh')}
`}

# ── 5. Move real SSH to port ${realPort} ──────────────────────────────────
SSH_DROPIN=/etc/ssh/sshd_config.d/99-secureforge.conf
if [ -f "$SSH_DROPIN" ]; then
  sed -i "s/^Port .*/Port ${realPort}/" "$SSH_DROPIN" || \
    echo "Port ${realPort}" >> "$SSH_DROPIN"
else
  mkdir -p /etc/ssh/sshd_config.d
  echo "Port ${realPort}" > "$SSH_DROPIN"
fi
echo "[!] REAL SSH moved to port ${realPort}. Update your firewall rules."
echo "[!] SSH command going forward: ssh -p ${realPort} user@host"

${banAfter ? `
# ── 6. fail2ban rule to auto-ban tarpit repeat offenders ──────────────
mkdir -p /etc/fail2ban/filter.d /etc/fail2ban/jail.d

cat > /etc/fail2ban/filter.d/endlessh.conf << 'F2BFILT'
[Definition]
failregex = ^.* endlessh .*ACCEPT .* <HOST> .*$
            ^.* endlessh.*NEW.*<HOST>.*$
ignoreregex =
F2BFILT

cat > /etc/fail2ban/jail.d/endlessh.conf << 'F2BJAIL'
[endlessh]
enabled  = true
filter   = endlessh
logpath  = /var/log/syslog /var/log/messages
maxretry = ${banHits}
bantime  = 7d
findtime = 1h
F2BJAIL
` : ''}

echo "[+] SSH Tarpit (endlessh) running on port ${tarpitPort}."
echo "[!] Real SSH is now on port ${realPort} — update SSH clients and firewall."
`;
  },

  manifests({ options }) {
    return {
      created: [
        '/etc/endlessh/config',
        '/usr/local/sbin/endlessh',
        '/etc/systemd/system/endlessh.service',
        ...(options.banAfter ? ['/etc/fail2ban/filter.d/endlessh.conf', '/etc/fail2ban/jail.d/endlessh.conf'] : []),
      ],
    };
  },
};
