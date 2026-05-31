export default {
  id: 'firewall',
  name: 'Firewall',
  description: 'nftables or awall — Alpine-native firewall, OpenRC service',
  category: 'Network',
  defaultEnabled: true,

  options: [
    { id: 'backend',      type: 'list',    label: 'Firewall backend:', default: 'nftables',
      choices: [
        { name: 'nftables (recommended for Alpine)',  value: 'nftables' },
        { name: 'awall (Alpine Wall — higher-level)', value: 'awall' },
        { name: 'iptables (legacy)',                  value: 'iptables' },
      ]
    },
    { id: 'sshRateLimit', type: 'confirm', label: 'Rate-limit SSH connections?', default: true },
    { id: 'denyPing',     type: 'confirm', label: 'Block external ICMP ping?',   default: false },
    { id: 'logDropped',   type: 'confirm', label: 'Log dropped packets?',        default: true },
    { id: 'customPorts',  type: 'input',   label: 'Extra open ports:',           default: '' },
  ],

  generate({ role, exposure, options }) {
    const backend    = options.backend      ?? 'nftables';
    const rateLimit  = options.sshRateLimit ?? true;
    const denyPing   = options.denyPing     ?? false;
    const logDropped = options.logDropped   ?? true;
    const customPorts = (options.customPorts ?? '').split(',').map(p => p.trim()).filter(Boolean);
    const isWeb  = role === 'web_server';
    const isVPN  = role === 'vpn_gateway';

    if (backend === 'awall') {
      return `
# ── Firewall: awall (Alpine) ──────────────────────────────────────────
# [ALPHA]
apk add --no-cache awall ip6tables

mkdir -p /etc/awall
cat > /etc/awall/optional/secureforge.json << 'AWJSON'
{
  "description": "SecureForge base policy",
  "import": [],
  "zone": {
    "inet": { "iface": "" }
  },
  "policy": [
    { "in": "inet", "action": "drop" }
  ],
  "filter": [
    { "in": "inet", "service": "ssh",  "action": "accept"${rateLimit ? ', "conn-limit": {"count": 5, "interval": 60}' : ''} },
    ${isWeb ? '{ "in": "inet", "service": ["http", "https"], "action": "accept" },' : ''}
    { "in": "_fw", "action": "accept" }
  ]
}
AWJSON

awall enable secureforge 2>/dev/null || true
awall activate --force 2>/dev/null || true
rc-update add iptables  default 2>/dev/null || true
rc-update add ip6tables default 2>/dev/null || true
`;
    }

    return `
# ── Firewall: nftables (Alpine) ───────────────────────────────────────
# [ALPHA]
apk add --no-cache nftables

cat > /etc/nftables.nft << 'NFT'
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iif lo accept
    ip  protocol icmp  ${denyPing ? 'drop' : 'accept'}
    ip6 nexthdr icmpv6 accept
    tcp dport 22 ${rateLimit ? 'limit rate 5/minute burst 10 packets' : ''} accept
    ${isWeb ? 'tcp dport { 80, 443 } accept' : ''}
    ${isVPN ? 'udp dport 1194 accept' : ''}
    ${customPorts.map(p => `tcp dport ${p} accept`).join('\n    ')}
    ${logDropped ? 'log prefix "sf-drop: " drop' : 'drop'}
  }
  chain forward { type filter hook forward priority 0; policy drop; }
  chain output  { type filter hook output  priority 0; policy accept; }
}
NFT

rc-update add nftables default
rc-service nftables start
`;
  },

  manifests() {
    return { created: ['/etc/nftables.nft'] };
  },
};
