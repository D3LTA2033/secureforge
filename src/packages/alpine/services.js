export default {
  id: 'services',
  name: 'Service Hardening',
  description: 'Disable risky OpenRC services, BusyBox hardening, cron restriction',
  category: 'Services',
  defaultEnabled: true,

  options: [
    { id: 'disableAvahi',   type: 'confirm', label: 'Disable Avahi?',               default: true },
    { id: 'disableTelnet',  type: 'confirm', label: 'Remove busybox telnet?',        default: true },
    { id: 'disableSysRq',   type: 'confirm', label: 'Disable Magic SysRq?',          default: true },
    { id: 'restrictCron',   type: 'confirm', label: 'Restrict cron to root only?',   default: false },
    { id: 'hardenBusybox',  type: 'confirm', label: 'Remove dangerous busybox applets?', default: false },
    { id: 'disableCoredump',type: 'confirm', label: 'Disable coredumps?',            default: true },
  ],

  generate({ options }) {
    const disableList = [];
    if (options.disableAvahi) disableList.push('avahi-daemon');

    return `
# ── Service Hardening (Alpine) ────────────────────────────────────────
# [ALPHA] Alpine uses OpenRC and BusyBox.

${disableList.map(svc => `
if rc-service ${svc} status &>/dev/null; then
  rc-service ${svc} stop 2>/dev/null || true
  rc-update del ${svc} default 2>/dev/null || true
fi
`).join('')}

${options.disableTelnet ? `
# Remove telnet applet from BusyBox if present
which telnet 2>/dev/null && {
  apk del busybox-extras 2>/dev/null || true
}
` : ''}

${options.disableSysRq ? `
echo 0 > /proc/sys/kernel/sysrq
echo 'kernel.sysrq = 0' > /etc/sysctl.d/99-sf-sysrq.conf
` : ''}

${options.disableCoredump ? `
echo '* hard core 0' >> /etc/security/limits.conf 2>/dev/null || true
` : ''}

${options.hardenBusybox ? `
# Remove potentially dangerous BusyBox applets
# (remove symlinks for applets that shouldn't be on a hardened server)
for applet in ftpd ftpget ftpput httpd telnetd tftp tftpd; do
  BIN_PATH=$(which "$applet" 2>/dev/null)
  if [ -n "$BIN_PATH" ] && [ "$(readlink "$BIN_PATH")" = "busybox" ]; then
    rm -f "$BIN_PATH"
    echo "[+] Removed BusyBox applet: $applet"
  fi
done
` : ''}

${options.restrictCron ? `
echo 'root' > /etc/cron.allow && chmod 600 /etc/cron.allow 2>/dev/null || true
` : ''}

# Ensure crond is running (needed for periodic scripts)
rc-update add crond default 2>/dev/null || true
rc-service crond start  2>/dev/null || true
`;
  },

  manifests({ options }) {
    return { disabled_services: [...(options.disableAvahi ? ['avahi-daemon'] : [])] };
  },
};
