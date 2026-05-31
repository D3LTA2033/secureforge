export default {
  id: 'services',
  name: 'Service Hardening',
  description: 'Disable risky OpenRC services, portage-based removal, cron restriction',
  category: 'Services',
  defaultEnabled: true,

  options: [
    { id: 'disableAvahi',   type: 'confirm', label: 'Disable Avahi?',           default: true },
    { id: 'disableCups',    type: 'confirm', label: 'Disable CUPS?',            default: true },
    { id: 'disableBt',      type: 'confirm', label: 'Disable Bluetooth?',       default: true },
    { id: 'removeTelnet',   type: 'confirm', label: 'Remove telnet?',           default: true },
    { id: 'restrictCron',   type: 'confirm', label: 'Restrict cron to root?',   default: false },
    { id: 'disableSysRq',   type: 'confirm', label: 'Disable Magic SysRq?',     default: true },
  ],

  generate({ options }) {
    const disableList = [];
    if (options.disableAvahi) disableList.push('avahi-daemon');
    if (options.disableCups)  disableList.push('cupsd');
    if (options.disableBt)    disableList.push('bluetooth');

    return `
# ── Service Hardening (Gentoo) ────────────────────────────────────────
# [ALPHA] Uses OpenRC for service management.

${disableList.map(svc => `
if rc-service ${svc} status &>/dev/null; then
  rc-service ${svc} stop 2>/dev/null || true
  rc-update del ${svc} default 2>/dev/null || true
  echo "[+] Disabled: ${svc}"
fi
`).join('')}

${options.removeTelnet ? `
emerge --ask=n --unmerge net-misc/telnet-bsd 2>/dev/null || true
` : ''}

${options.disableSysRq ? `
echo 0 > /proc/sys/kernel/sysrq
echo 'kernel.sysrq = 0' > /etc/sysctl.d/99-sf-sysrq.conf
` : ''}

${options.restrictCron ? `
echo 'root' > /etc/cron.allow && chmod 600 /etc/cron.allow
echo 'ALL' > /etc/cron.deny   && chmod 600 /etc/cron.deny 2>/dev/null || true
` : ''}

# Harden sshd OpenRC conf
cat > /etc/conf.d/sshd << 'SSHDCONF'
# SecureForge: sshd OpenRC config
SSHD_CONFDIR="/etc/ssh"
SSHD_OPTS=""
SSHDCONF
`;
  },

  manifests({ options }) {
    return { disabled_services: [...(options.disableAvahi ? ['avahi-daemon'] : []), ...(options.disableCups ? ['cupsd'] : [])] };
  },
};
