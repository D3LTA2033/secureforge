import { SYSCTL_NETWORK } from '../shared/sysctl.js';

export default {
  id: 'network',
  name: 'Network Hardening',
  description: 'sysctl network stack, disable unused protocols, DNS-over-TLS',
  category: 'Network',
  defaultEnabled: true,

  options: [
    { id: 'disableIPv6',      type: 'confirm', label: 'Disable IPv6?',                           default: false },
    { id: 'dnsOverTLS',       type: 'confirm', label: 'Enable DNS-over-TLS (systemd-resolved)?', default: false },
    { id: 'disableBluetooth', type: 'confirm', label: 'Disable Bluetooth at kernel level?',      default: true },
    { id: 'disableWifi',      type: 'confirm', label: 'Disable Wi-Fi at kernel level?',          default: false },
    { id: 'tcpHarden',        type: 'confirm', label: 'TCP SYN hardening + timestamp removal?',  default: true },
    { id: 'disableProtocols', type: 'confirm', label: 'Blacklist unused network protocols?',     default: true },
  ],

  generate({ options }) {
    const ipv6     = options.disableIPv6      ?? false;
    const dotls    = options.dnsOverTLS       ?? false;
    const nobt     = options.disableBluetooth ?? true;
    const nowifi   = options.disableWifi      ?? false;
    const noProto  = options.disableProtocols ?? true;

    return `
# ── Network Hardening (Arch) ─────────────────────────────────────────

# sysctl network rules
cat > /etc/sysctl.d/99-sf-network.conf << 'EOF'
${SYSCTL_NETWORK}
${ipv6 ? `
# Disable IPv6 entirely
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
` : ''}
EOF

sysctl --system --load /etc/sysctl.d/99-sf-network.conf

${noProto ? `
# Blacklist unused/dangerous network protocols
cat > /etc/modprobe.d/sf-net-protocols.conf << 'MODS'
install dccp    /bin/false
install sctp    /bin/false
install rds     /bin/false
install tipc    /bin/false
install n-hdlc  /bin/false
install ax25    /bin/false
install netrom  /bin/false
install x25     /bin/false
install rose    /bin/false
install decnet  /bin/false
install econet  /bin/false
install af_802154 /bin/false
install ipx     /bin/false
install appletalk /bin/false
install psnap   /bin/false
install p8023   /bin/false
install p8022   /bin/false
MODS
` : ''}

${nobt ? `
# Disable Bluetooth kernel module
echo 'install bluetooth /bin/false' >> /etc/modprobe.d/sf-net-protocols.conf
echo 'blacklist bluetooth'          >> /etc/modprobe.d/sf-net-protocols.conf
echo 'blacklist btusb'              >> /etc/modprobe.d/sf-net-protocols.conf
systemctl disable --now bluetooth 2>/dev/null || true
` : ''}

${nowifi ? `
# Disable WiFi kernel modules
echo 'install cfg80211 /bin/false' >> /etc/modprobe.d/sf-net-protocols.conf
echo 'install mac80211 /bin/false' >> /etc/modprobe.d/sf-net-protocols.conf
` : ''}

${dotls ? `
# DNS-over-TLS via systemd-resolved
mkdir -p /etc/systemd/resolved.conf.d
cat > /etc/systemd/resolved.conf.d/sf-dotls.conf << 'DOTLS'
[Resolve]
DNS=1.1.1.1#cloudflare-dns.com 9.9.9.9#dns.quad9.net
DNSSEC=allow-downgrade
DNSOverTLS=opportunistic
Domains=~.
DOTLS
systemctl enable --now systemd-resolved
ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
` : ''}

# Disable IPv6 in GRUB cmdline too if requested
${ipv6 ? `
GRUB_FILE=/etc/default/grub
if grep -q 'GRUB_CMDLINE_LINUX=' "$GRUB_FILE"; then
  sed -i 's/GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 ipv6.disable=1"/' "$GRUB_FILE"
  grub-mkconfig -o /boot/grub/grub.cfg 2>/dev/null || true
fi
` : ''}
`;
  },

  manifests() {
    return {
      created: [
        '/etc/sysctl.d/99-sf-network.conf',
        '/etc/modprobe.d/sf-net-protocols.conf',
      ],
    };
  },
};
