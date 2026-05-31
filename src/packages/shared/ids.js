import { pm, pkg } from './pkg.js';

export default {
  id: 'ids',
  name: 'Suricata IDS',
  description: 'Network intrusion detection: Suricata with community rules, alert on threats',
  category: 'Monitoring',
  defaultEnabled: false,

  options: [
    { id: 'mode',        type: 'list',    label: 'Suricata mode:',  default: 'ids',
      choices: [
        { name: 'IDS — alert only (safe, no traffic impact)',  value: 'ids' },
        { name: 'IPS — inline drop mode (requires nfqueue)',   value: 'ips' },
      ]
    },
    { id: 'interface',   type: 'input',   label: 'Network interface to monitor (blank = auto-detect):', default: '' },
    { id: 'communityRules', type: 'confirm', label: 'Download Suricata community rules?',               default: true },
    { id: 'etRules',     type: 'confirm', label: 'Download Emerging Threats open rules?',               default: true },
    { id: 'homeNet',     type: 'input',   label: 'HOME_NET (your internal network, e.g. 192.168.0.0/16):', default: '192.168.0.0/16,10.0.0.0/8,172.16.0.0/12' },
    { id: 'logEve',      type: 'confirm', label: 'Enable JSON event log (eve.json)?',                   default: true },
    { id: 'dailyRuleUpdate', type: 'confirm', label: 'Auto-update rules daily via cron?',               default: true },
  ],

  generate({ distro, options }) {
    const mode       = options.mode            ?? 'ids';
    const iface      = options.interface?.trim() ?? '';
    const commRules  = options.communityRules  ?? true;
    const etRules    = options.etRules         ?? true;
    const homeNet    = options.homeNet         ?? '192.168.0.0/16,10.0.0.0/8,172.16.0.0/12';
    const logEve     = options.logEve          ?? true;
    const autoUpdate = options.dailyRuleUpdate ?? true;

    // EPEL required for RHEL/CentOS
    const epelNote = ['rhel', 'centos'].includes(distro)
      ? '# Suricata requires EPEL on RHEL/CentOS\ndnf install -y epel-release 2>/dev/null || true\n'
      : '';

    return `
# ── Suricata IDS (${distro}) ──────────────────────────────────────────
${epelNote}${pm(distro)(pkg(distro, 'suricata'))}

# Detect primary interface if not specified
IFACE="${iface}"
[ -z "$IFACE" ] && IFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
[ -z "$IFACE" ] && IFACE=$(ip link show | awk -F': ' '/^[0-9]+: [^lo]/ {print $2; exit}')
echo "[i] Monitoring interface: $IFACE"

# Backup and write Suricata config
[ -f /etc/suricata/suricata.yaml ] && cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.sf.bak

cat > /etc/suricata/suricata.yaml << SURICFG
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[${homeNet}]"
    EXTERNAL_NET: "!\$HOME_NET"
  port-groups:
    HTTP_PORTS:  "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502
    FILE_DATA_PORTS: "[\$HTTP_PORTS,110,143]"
    FTP_PORTS: 21

af-packet:
  - interface: \$IFACE
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes

${logEve ? `
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert
        - http
        - dns
        - tls
        - files
        - ssh
        - flow
  - fast:
      enabled: yes
      filename: /var/log/suricata/fast.log
      append: yes
` : `
outputs:
  - fast:
      enabled: yes
      filename: /var/log/suricata/fast.log
`}

logging:
  default-log-level: notice
  outputs:
    - console:
        enabled: yes
    - file:
        enabled: yes
        level: info
        filename: /var/log/suricata/suricata.log

rule-files:
  - /etc/suricata/rules/*.rules

default-rule-path: /etc/suricata/rules
SURICFG

mkdir -p /etc/suricata/rules /var/log/suricata

${commRules ? `
# Download Suricata community ruleset
suricata-update update-sources 2>/dev/null || true
suricata-update enable-source et/open 2>/dev/null || true
suricata-update 2>/dev/null || true
` : ''}

${etRules ? `
# Download Emerging Threats Open rules
ET_URL="https://rules.emergingthreats.net/open/suricata-7.0/emerging.rules.tar.gz"
TMPFILE=$(mktemp /tmp/et-rules.XXXXXX.tar.gz)
curl -sSL "$ET_URL" -o "$TMPFILE" 2>/dev/null && \
  tar -xzf "$TMPFILE" -C /etc/suricata/rules/ --strip-components=1 2>/dev/null || \
  echo "[!] ET rules download failed — run 'suricata-update' manually"
rm -f "$TMPFILE"
` : ''}

# Write systemd service for Suricata
cat > /etc/systemd/system/suricata.service << 'SVCEOF'
[Unit]
Description=Suricata IDS/IPS
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
ExecStart=/usr/sbin/suricata ${mode === 'ips' ? '--af-packet -D -q 0' : '-c /etc/suricata/suricata.yaml --af-packet -D'}
ExecStop=/bin/kill -TERM \$MAINPID
PIDFile=/var/run/suricata.pid
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable --now suricata

${autoUpdate ? `
cat > /etc/cron.daily/sf-suricata-update << 'SURL'
#!/bin/bash
suricata-update 2>/dev/null && systemctl reload suricata 2>/dev/null || true
SURL
chmod 755 /etc/cron.daily/sf-suricata-update
` : ''}

echo "[+] Suricata IDS running in ${mode.toUpperCase()} mode on interface: $IFACE"
echo "[!] Check /var/log/suricata/fast.log for alerts."
`;
  },

  manifests({ options }) {
    return {
      created: [
        '/etc/suricata/suricata.yaml',
        '/etc/systemd/system/suricata.service',
        ...(options.dailyRuleUpdate ? ['/etc/cron.daily/sf-suricata-update'] : []),
      ],
      packages_installed: ['suricata'],
    };
  },
};
