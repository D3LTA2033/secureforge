import { SYSCTL_KERNEL, SYSCTL_FS } from '../shared/sysctl.js';

export default {
  id: 'kernel',
  name: 'Kernel Hardening',
  description: 'sysctl, hardened USE flags, PaX recommendations, genkernel config hints',
  category: 'Kernel',
  defaultEnabled: true,

  options: [
    { id: 'ptraceScope',      type: 'list',    label: 'ptrace scope:',
      choices: [
        { name: '0 — no restriction',          value: '0' },
        { name: '2 — admin only (recommended)', value: '2' },
      ], default: '2' },
    { id: 'hardenedProfile',  type: 'confirm', label: 'Switch to Gentoo hardened profile (recommended)?', default: false },
    { id: 'hardenedUSE',      type: 'confirm', label: 'Add hardened USE flags to make.conf?',              default: true },
    { id: 'hidePid',          type: 'confirm', label: 'hidepid=2 on /proc?',                               default: true },
    { id: 'disableUsb',       type: 'confirm', label: 'Disable USB storage?',                              default: false },
  ],

  generate({ options }) {
    const ptraceScope      = options.ptraceScope     ?? '2';
    const hardenedProfile  = options.hardenedProfile ?? false;
    const hardenedUSE      = options.hardenedUSE     ?? true;
    const hidePid          = options.hidePid         ?? true;
    const noUsb            = options.disableUsb      ?? false;

    return `
# ── Kernel Hardening (Gentoo) ─────────────────────────────────────────
# [ALPHA] Gentoo kernel hardening via sysctl + Portage USE flags.
# Note: Full PaX/grsecurity requires hardened-sources kernel — compile manually.

cat > /etc/sysctl.d/99-sf-kernel.conf << 'EOF'
${SYSCTL_KERNEL.replace('kernel.yama.ptrace_scope = 2', `kernel.yama.ptrace_scope = ${ptraceScope}`)}
${SYSCTL_FS}
EOF
sysctl --system

${hardenedUSE ? `
# Add hardening USE flags to make.conf
MAKECONF=/etc/portage/make.conf
grep -q 'SF_HARDEN' "$MAKECONF" || cat >> "$MAKECONF" << 'USEOF'
# SecureForge hardening USE flags
USE="\${USE} hardened pic pie ssp -bindist"
CFLAGS="\${CFLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE"
CXXFLAGS="\${CXXFLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE"
LDFLAGS="\${LDFLAGS} -Wl,-z,relro -Wl,-z,now -pie"
# SF_HARDEN=1
USEOF
echo "[+] Hardened USE flags added to make.conf."
echo "[!] Re-emerge world to apply: emerge --ask -uDN @world"
` : ''}

${hardenedProfile ? `
# Switch to hardened profile
CURRENT_PROFILE=$(eselect profile show 2>/dev/null | tail -1)
echo "[i] Current profile: $CURRENT_PROFILE"
# List hardened profiles
eselect profile list | grep -i hardened || true
echo "[!] To switch: eselect profile set <number>"
echo "[!] Then run: emerge --ask -uDN @world"
` : ''}

${hidePid ? `
if ! grep -q 'hidepid' /etc/fstab; then
  echo 'proc /proc proc defaults,hidepid=2,gid=proc 0 0' >> /etc/fstab
fi
groupadd -f proc
` : ''}

cat > /etc/modprobe.d/sf-kernel.conf << 'MODS'
${noUsb ? 'install usb_storage /bin/false\nblacklist usb_storage' : ''}
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
