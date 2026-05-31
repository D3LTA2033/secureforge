import { SYSCTL_KERNEL, SYSCTL_FS } from '../shared/sysctl.js';

export default {
  id: 'kernel',
  name: 'Kernel Hardening',
  description: 'sysctl, module blacklists, Alpine hardened kernel option',
  category: 'Kernel',
  defaultEnabled: true,

  options: [
    { id: 'hardenedKernel', type: 'confirm', label: 'Install alpine-hardened kernel (linux-hardened)?', default: false },
    { id: 'ptraceScope',    type: 'list',    label: 'ptrace scope:',
      choices: [
        { name: '0 — no restriction',          value: '0' },
        { name: '2 — admin only (recommended)', value: '2' },
      ], default: '2' },
    { id: 'hidePid',        type: 'confirm', label: 'hidepid=2 on /proc?',              default: true },
    { id: 'disableUsb',     type: 'confirm', label: 'Disable USB storage?',              default: false },
    { id: 'disableFirewire',type: 'confirm', label: 'Disable Firewire?',                 default: true },
  ],

  generate({ options }) {
    const hardenedK   = options.hardenedKernel ?? false;
    const ptraceScope = options.ptraceScope    ?? '2';
    const hidePid     = options.hidePid        ?? true;
    const noUsb       = options.disableUsb     ?? false;
    const noFirewire  = options.disableFirewire ?? true;

    return `
# ── Kernel Hardening (Alpine) ─────────────────────────────────────────
# [ALPHA] Alpine-specific kernel hardening.

${hardenedK ? `
# Install Alpine hardened kernel
apk add --no-cache linux-hardened linux-hardened-dev 2>/dev/null || \
  echo "[!] linux-hardened not available for your Alpine version/arch."
echo "[!] Reboot required to switch to hardened kernel after install."
` : ''}

cat > /etc/sysctl.d/99-sf-kernel.conf << 'EOF'
${SYSCTL_KERNEL.replace('kernel.yama.ptrace_scope = 2', `kernel.yama.ptrace_scope = ${ptraceScope}`)}
${SYSCTL_FS}
EOF
sysctl -p /etc/sysctl.d/99-sf-kernel.conf 2>/dev/null || sysctl --system

${hidePid ? `
if ! grep -q 'hidepid' /etc/fstab; then
  echo 'proc /proc proc defaults,hidepid=2,gid=proc 0 0' >> /etc/fstab
fi
addgroup -S proc 2>/dev/null || groupadd -f proc 2>/dev/null || true
` : ''}

cat > /etc/modprobe.d/sf-kernel.conf << 'MODS'
${noUsb      ? 'install usb_storage /bin/false\nblacklist usb_storage' : ''}
${noFirewire ? 'install firewire-core /bin/false\nblacklist firewire-core' : ''}
install cramfs   /bin/false
install freevxfs /bin/false
install jffs2    /bin/false
install hfs      /bin/false
install hfsplus  /bin/false
MODS
`;
  },

  manifests() {
    return { created: ['/etc/sysctl.d/99-sf-kernel.conf', '/etc/modprobe.d/sf-kernel.conf'] };
  },
};
