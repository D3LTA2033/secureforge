import { SYSCTL_NETWORK } from '../shared/sysctl.js';

export default {
  id: 'network',
  name: 'Network Hardening',
  description: 'sysctl stack, protocol blacklist, Portage-aware, OpenRC network config',
  category: 'Network',
  defaultEnabled: true,

  options: [
    { id: 'disableIPv6',      type: 'confirm', label: 'Disable IPv6?',                          default: false },
    { id: 'disableBluetooth', type: 'confirm', label: 'Disable Bluetooth?',                     default: true },
    { id: 'disableProtocols', type: 'confirm', label: 'Blacklist unused network protocols?',    default: true },
    { id: 'syncPortage',      type: 'confirm', label: 'Sync Portage tree before installing?',   default: false },
  ],

  generate({ options }) {
    const ipv6    = options.disableIPv6      ?? false;
    const nobt    = options.disableBluetooth ?? true;
    const noProto = options.disableProtocols ?? true;
    const sync    = options.syncPortage      ?? false;

    return `
# ── Network Hardening (Gentoo) ────────────────────────────────────────
# [ALPHA] Note: emerge operations may take significant time on Gentoo.
${sync ? 'emerge --sync 2>/dev/null || true' : ''}

cat > /etc/sysctl.d/99-sf-network.conf << 'EOF'
${SYSCTL_NETWORK}
${ipv6 ? `
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
` : ''}
EOF
sysctl --system

${noProto ? `
cat > /etc/modprobe.d/sf-net-protocols.conf << 'MODS'
install dccp    /bin/false
install sctp    /bin/false
install rds     /bin/false
install tipc    /bin/false
install ax25    /bin/false
install netrom  /bin/false
install x25     /bin/false
install decnet  /bin/false
install ipx     /bin/false
install appletalk /bin/false
MODS
` : ''}

${nobt ? `
echo 'install bluetooth /bin/false' >> /etc/modprobe.d/sf-net-protocols.conf
rc-service bluetooth stop 2>/dev/null || true
rc-update del bluetooth default 2>/dev/null || true
` : ''}
`;
  },

  manifests() {
    return { created: ['/etc/sysctl.d/99-sf-network.conf', '/etc/modprobe.d/sf-net-protocols.conf'] };
  },
};
