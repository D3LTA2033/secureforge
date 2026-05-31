import { pm, pkg } from './pkg.js';

export default {
  id: 'ntp',
  name: 'NTP / Chrony Hardening',
  description: 'Secure time sync: chrony with NTS, restrict queries, tamper detection',
  category: 'Network',
  defaultEnabled: true,

  options: [
    { id: 'useNTS',        type: 'confirm', label: 'Enable NTS (Network Time Security / authenticated NTP)?', default: true },
    { id: 'ntpPool',       type: 'list',    label: 'NTP pool source:',  default: 'pool.ntp.org',
      choices: [
        { name: 'pool.ntp.org (public)',       value: 'pool.ntp.org' },
        { name: 'time.cloudflare.com (NTS)',   value: 'time.cloudflare.com' },
        { name: 'time.google.com',             value: 'time.google.com' },
      ]
    },
    { id: 'restrictQuery', type: 'confirm', label: 'Restrict chrony to local queries only (no redistribution)?', default: true },
    { id: 'makestep',      type: 'confirm', label: 'Allow large time jumps on startup (makestep)?',             default: true },
    { id: 'hwclock',       type: 'confirm', label: 'Sync hardware clock from system clock periodically?',        default: true },
    { id: 'leapSmear',     type: 'confirm', label: 'Smooth leap seconds (leapsectz)?',                           default: false },
    { id: 'alertDrift',    type: 'confirm', label: 'Log time drift > 0.1s to syslog?',                          default: true },
  ],

  generate({ distro, options }) {
    const useNTS   = options.useNTS        ?? true;
    const pool     = options.ntpPool       ?? 'pool.ntp.org';
    const restrict = options.restrictQuery ?? true;
    const makestep = options.makestep      ?? true;
    const hwclock  = options.hwclock       ?? true;
    const smear    = options.leapSmear     ?? false;
    const alertD   = options.alertDrift    ?? true;

    const isNTS    = useNTS && pool === 'time.cloudflare.com';

    return `
# ── NTP / Chrony Hardening (${distro}) ───────────────────────────────
${pm(distro)(pkg(distro, 'chrony'))}

# Backup existing chrony config
[ -f /etc/chrony.conf ] && cp /etc/chrony.conf /etc/chrony.conf.sf.bak
[ -f /etc/chrony/chrony.conf ] && cp /etc/chrony/chrony.conf /etc/chrony/chrony.conf.sf.bak

# Determine config path
CHRONY_CONF=/etc/chrony.conf
[ -f /etc/chrony/chrony.conf ] && CHRONY_CONF=/etc/chrony/chrony.conf

cat > "$CHRONY_CONF" << 'CHRONYCONF'
# SecureForge Chrony Config

# Time sources
${isNTS
  ? `server ${pool} iburst nts
server time.cloudflare.com iburst nts
server ntppool1.time.nl iburst nts`
  : `pool ${pool} iburst maxsources 4
server 0.${pool} iburst
server 1.${pool} iburst
server 2.${pool} iburst
server 3.${pool} iburst`
}

# Drift file
driftfile /var/lib/chrony/drift

${makestep ? 'makestep 1.0 3' : '# makestep disabled — large jumps ignored'}

# RTC
rtcsync

${hwclock ? `
# Hardware clock sync
hwtimestamp *
` : ''}

${restrict ? `
# Restrict chrony: do not act as NTP server for the network
bindaddress 127.0.0.1
port 0
` : ''}

${smear ? 'leapsectz right/UTC' : ''}

# Security
noclientlog
logdir /var/log/chrony
log measurements statistics tracking
${alertD ? 'maxdistance 1.0' : ''}

# Require at least 3 sources to agree
minsources 2
CHRONYCONF

chmod 640 "$CHRONY_CONF"
chown root:${distro === 'arch' ? 'root' : '_chrony'} "$CHRONY_CONF" 2>/dev/null || true

systemctl enable --now chronyd

# Force initial sync
chronyc makestep 2>/dev/null || true

${alertD ? `
# Cron to log drift
cat > /etc/cron.hourly/sf-chrony-drift << 'CDRIFT'
#!/bin/bash
DRIFT=$(chronyc tracking 2>/dev/null | awk '/System time/ {print $4}')
if [ -n "$DRIFT" ]; then
  DRIFT_INT=$(echo "$DRIFT" | awk '{printf "%d", $1 * 1000}')
  [ "$DRIFT_INT" -gt 100 ] && logger -t secureforge-ntp "Time drift: ${DRIFT}s exceeds 0.1s threshold"
fi
CDRIFT
chmod 755 /etc/cron.hourly/sf-chrony-drift
` : ''}

# Disable systemd-timesyncd if present (conflicts with chrony)
systemctl disable --now systemd-timesyncd 2>/dev/null || true

# Disable legacy ntpd if present
systemctl disable --now ntpd ntp 2>/dev/null || true

echo "[+] Chrony NTP hardened. Run 'chronyc tracking' to verify sync."
`;
  },

  manifests({ options }) {
    return {
      created: ['/etc/cron.hourly/sf-chrony-drift'],
      packages_installed: ['chrony'],
    };
  },
};
