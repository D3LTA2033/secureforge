export default {
  id: 'firewall',
  name: 'Firewall',
  description: 'nftables via Portage, OpenRC service, role-based rules',
  category: 'Network',
  defaultEnabled: true,

  options: [
    { id: 'sshRateLimit', type: 'confirm', label: 'Rate-limit SSH connections?',          default: true },
    { id: 'denyPing',     type: 'confirm', label: 'Block external ICMP ping?',             default: false },
    { id: 'logDropped',   type: 'confirm', label: 'Log dropped packets?',                 default: true },
    { id: 'customPorts',  type: 'input',   label: 'Extra open ports (e.g. 8080,9200):',   default: '' },
  ],

  generate({ role, exposure, options }) {
    const rateLimit   = options.sshRateLimit ?? true;
    const denyPing    = options.denyPing     ?? false;
    const logDropped  = options.logDropped   ?? true;
    const customPorts = (options.customPorts ?? '').split(',').map(p => p.trim()).filter(Boolean);
    const isWeb       = role === 'web_server';
    const isVPN       = role === 'vpn_gateway';

    return `
# ── Firewall: nftables (Gentoo) ───────────────────────────────────────
# [ALPHA] Uses nftables via Portage + OpenRC.
emerge --ask=n net-firewall/nftables

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
    ${isWeb  ? 'tcp dport { 80, 443 } accept' : ''}
    ${isVPN  ? 'udp dport 1194 accept' : ''}
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
    return { created: ['/etc/nftables.conf'], packages_installed: ['net-firewall/nftables'] };
  },
};
