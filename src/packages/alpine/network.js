import { SYSCTL_NETWORK } from '../shared/sysctl.js';

export default {
  id: 'network',
  name: 'Network Hardening',
  description: 'sysctl stack, protocol blacklist, Alpine community repo, auto-upgrade',
  category: 'Network',
  defaultEnabled: true,

  options: [
    { id: 'enableCommunity',  type: 'confirm', label: 'Enable Alpine community repo (needed for many tools)?', default: true },
    { id: 'disableIPv6',      type: 'confirm', label: 'Disable IPv6?',                                        default: false },
    { id: 'disableBluetooth', type: 'confirm', label: 'Disable Bluetooth?',                                   default: true },
    { id: 'disableProtocols', type: 'confirm', label: 'Blacklist unused network protocols?',                  default: true },
    { id: 'autoUpgrade',      type: 'confirm', label: 'Enable daily apk upgrade via cron?',                   default: true },
  ],

  generate({ options }) {
    const community = options.enableCommunity  ?? true;
    const ipv6      = options.disableIPv6      ?? false;
    const nobt      = options.disableBluetooth ?? true;
    const noProto   = options.disableProtocols ?? true;
    const autoUpg   = options.autoUpgrade      ?? true;

    return `
# ── Network Hardening (Alpine) ────────────────────────────────────────
# [ALPHA] Alpine Linux uses apk and musl libc.

${community ? `
# Enable community repository
REPOS=/etc/apk/repositories
if ! grep -q 'community' "$REPOS"; then
  # Get current mirror and add community
  MIRROR=$(grep -m1 'http' "$REPOS" | sed 's|/v[0-9].*||')
  ALPINE_VER=$(cat /etc/alpine-release | cut -d. -f1,2)
  echo "${MIRROR}/v${ALPINE_VER}/community" >> "$REPOS"
fi
apk update
` : ''}

cat > /etc/sysctl.d/99-sf-network.conf << 'EOF'
${SYSCTL_NETWORK}
${ipv6 ? `
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
` : ''}
EOF
sysctl -p /etc/sysctl.d/99-sf-network.conf 2>/dev/null || sysctl --system

${noProto ? `
cat > /etc/modprobe.d/sf-net-protocols.conf << 'MODS'
install dccp    /bin/false
install sctp    /bin/false
install rds     /bin/false
install tipc    /bin/false
install ax25    /bin/false
install netrom  /bin/false
install x25     /bin/false
install ipx     /bin/false
install appletalk /bin/false
MODS
` : ''}

${nobt ? `
echo 'install bluetooth /bin/false' >> /etc/modprobe.d/sf-net-protocols.conf
echo 'blacklist bluetooth'          >> /etc/modprobe.d/sf-net-protocols.conf
` : ''}

${autoUpg ? `
# Daily auto-upgrade via OpenRC / cron
cat > /etc/periodic/daily/sf-apk-upgrade << 'APKUP'
#!/bin/sh
apk update -q && apk upgrade -q --no-cache 2>&1 | logger -t sf-apk-upgrade
APKUP
chmod 755 /etc/periodic/daily/sf-apk-upgrade
# Ensure crond runs
rc-update add crond default 2>/dev/null || true
rc-service crond start  2>/dev/null || true
` : ''}
`;
  },

  manifests() {
    return { created: ['/etc/sysctl.d/99-sf-network.conf', '/etc/modprobe.d/sf-net-protocols.conf'] };
  },
};
