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
    { id: 'tcpHarden',        type: 'confirm', label: 'TCP SYN hardening + timestamp removal?',  default: true },
    { id: 'disableProtocols', type: 'confirm', label: 'Blacklist unused network protocols?',     default: true },
    { id: 'unattendedUpgrades', type: 'confirm', label: 'Enable automatic security upgrades?',   default: true },
  ],

  generate({ options }) {
    const ipv6      = options.disableIPv6       ?? false;
    const dotls     = options.dnsOverTLS        ?? false;
    const nobt      = options.disableBluetooth  ?? true;
    const noProto   = options.disableProtocols  ?? true;
    const autoUpg   = options.unattendedUpgrades ?? true;

    return `
# ── Network Hardening (Debian) ────────────────────────────────────────
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq \
  ${autoUpg ? 'unattended-upgrades apt-listchanges' : ''} \
  ${dotls   ? 'systemd-resolved' : ''}

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
install econet  /bin/false
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

${autoUpg ? `
cat > /etc/apt/apt.conf.d/20auto-upgrades << 'APT'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APT

cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'APT2'
Unattended-Upgrade::Allowed-Origins {
  "\${distro_id}:\${distro_codename}-security";
  "\${distro_id}ESMApps:\${distro_codename}-apps-security";
};
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
APT2
systemctl enable --now unattended-upgrades
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
  sed -i 's/GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\\1 ipv6.disable=1"/' "$GRUB_FILE"
update-grub 2>/dev/null || true
` : ''}
`;
  },

  manifests() {
    return {
      created: ['/etc/sysctl.d/99-sf-network.conf', '/etc/modprobe.d/sf-net-protocols.conf'],
    };
  },
};
