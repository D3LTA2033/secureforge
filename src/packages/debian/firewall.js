export default {
  id: 'firewall',
  name: 'Firewall',
  description: 'UFW + nftables rules, role-based ports, rate limiting',
  category: 'Network',
  defaultEnabled: true,

  options: [
    { id: 'backend',      type: 'list',    label: 'Firewall backend:', default: 'ufw',
      choices: [
        { name: 'UFW (simple)',        value: 'ufw' },
        { name: 'nftables (advanced)', value: 'nftables' },
        { name: 'iptables (legacy)',   value: 'iptables' },
      ]
    },
    { id: 'sshRateLimit', type: 'confirm', label: 'Rate-limit SSH?',                   default: true },
    { id: 'denyPing',     type: 'confirm', label: 'Block external ICMP ping?',          default: false },
    { id: 'logDropped',   type: 'confirm', label: 'Log dropped packets?',               default: true },
    { id: 'customPorts',  type: 'input',   label: 'Extra open ports (e.g. 8080,9200):', default: '' },
  ],

  generate({ role, exposure, options }) {
    const backend    = options.backend      ?? 'ufw';
    const rateLimit  = options.sshRateLimit ?? true;
    const denyPing   = options.denyPing     ?? false;
    const logDropped = options.logDropped   ?? true;
    const customPorts = (options.customPorts ?? '').split(',').map(p => p.trim()).filter(Boolean);

    const isWeb  = role === 'web_server';
    const isVPN  = role === 'vpn_gateway';
    const internet = exposure === 'internet';

    if (backend === 'nftables') {
      return `
# ── Firewall: nftables (Debian) ───────────────────────────────────────
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq nftables

cat > /etc/nftables.conf << 'NFT'
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

systemctl enable --now nftables
`;
    }

    return `
# ── Firewall: UFW (Debian) ────────────────────────────────────────────
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq ufw

ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw default deny forward

${rateLimit || internet ? 'ufw limit ssh' : 'ufw allow ssh'}
${isWeb  ? 'ufw allow 80/tcp\nufw allow 443/tcp' : ''}
${isVPN  ? 'ufw allow 1194/udp' : ''}
${denyPing ? `echo 'net/ipv4/icmp_echo_ignore_all=1' >> /etc/ufw/sysctl.conf` : ''}
${logDropped ? 'ufw logging on' : ''}
${customPorts.map(p => `ufw allow ${p}/tcp`).join('\n')}

ufw --force enable
systemctl enable ufw
`;
  },

  manifests({ options }) {
    return {
      packages_installed: [options.backend === 'nftables' ? 'nftables' : 'ufw'],
    };
  },
};
