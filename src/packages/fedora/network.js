import { SYSCTL_NETWORK } from '../shared/sysctl.js';

export default {
  id: 'network',
  name: 'Network Hardening',
  description: 'sysctl network stack, protocol blacklist, DNS-over-TLS, auto-updates',
  category: 'Network',
  defaultEnabled: true,

  options: [
    { id: 'disableIPv6',       type: 'confirm', label: 'Disable IPv6?',                           default: false },
    { id: 'dnsOverTLS',        type: 'confirm', label: 'Enable DNS-over-TLS (systemd-resolved)?', default: false },
    { id: 'disableBluetooth',  type: 'confirm', label: 'Disable Bluetooth at kernel level?',      default: true },
    { id: 'disableProtocols',  type: 'confirm', label: 'Blacklist unused network protocols?',     default: true },
    { id: 'autoUpdates',       type: 'confirm', label: 'Enable dnf-automatic security updates?',  default: true },
  ],

  generate({ options }) {
    const ipv6     = options.disableIPv6      ?? false;
    const dotls    = options.dnsOverTLS       ?? false;
    const nobt     = options.disableBluetooth ?? true;
    const noProto  = options.disableProtocols ?? true;
    const autoUpd  = options.autoUpdates      ?? true;

    return `
# ── Network Hardening (Fedora) ────────────────────────────────────────
${autoUpd ? 'dnf install -y dnf-automatic' : ''}

cat > /etc/sysctl.d/99-sf-network.conf << 'EOF'
${SYSCTL_NETWORK}
${ipv6 ? `
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
` : ''}
EOF
sysctl --system

${noProto ? `
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
install af_802154 /bin/false
install ipx     /bin/false
install appletalk /bin/false
MODS
` : ''}

${nobt ? `
echo 'install bluetooth /bin/false' >> /etc/modprobe.d/sf-net-protocols.conf
echo 'blacklist bluetooth'          >> /etc/modprobe.d/sf-net-protocols.conf
systemctl disable --now bluetooth 2>/dev/null || true
` : ''}

${autoUpd ? `
sed -i 's/^apply_updates = .*/apply_updates = yes/' /etc/dnf/automatic.conf
sed -i 's/^upgrade_type = .*/upgrade_type = security/' /etc/dnf/automatic.conf
sed -i 's/^emit_via = .*/emit_via = stdio/' /etc/dnf/automatic.conf
systemctl enable --now dnf-automatic.timer
` : ''}

${dotls ? `
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

${ipv6 ? `
GRUB_FILE=/etc/default/grub
grep -q 'ipv6.disable' "$GRUB_FILE" || \
  sed -i 's/GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 ipv6.disable=1"/' "$GRUB_FILE"
grub2-mkconfig -o /boot/grub2/grub.cfg 2>/dev/null || grub2-mkconfig -o /boot/efi/EFI/fedora/grub.cfg 2>/dev/null || true
` : ''}
`;
  },

  manifests() {
    return {
      created: ['/etc/sysctl.d/99-sf-network.conf', '/etc/modprobe.d/sf-net-protocols.conf'],
      packages_installed: ['dnf-automatic'],
    };
  },
};
