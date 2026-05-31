import { SYSCTL_KERNEL, SYSCTL_FS } from '../shared/sysctl.js';

export default {
  id: 'kernel',
  name: 'Kernel Hardening',
  description: 'ASLR, ptrace, BPF, AppArmor enforcing, module blacklists',
  category: 'Kernel',
  defaultEnabled: true,

  options: [
    { id: 'ptraceScope',    type: 'list',    label: 'ptrace scope:',
      choices: [
        { name: '0 — no restriction',           value: '0' },
        { name: '1 — child processes only',     value: '1' },
        { name: '2 — admin only (recommended)', value: '2' },
        { name: '3 — fully disabled',           value: '3' },
      ], default: '2' },
    { id: 'apparmor',       type: 'confirm', label: 'Enable AppArmor + enforce all profiles?',   default: true },
    { id: 'hidePid',        type: 'confirm', label: 'hidepid=2 on /proc?',                        default: true },
    { id: 'disableUsb',     type: 'confirm', label: 'Disable USB storage?',                       default: false },
    { id: 'disableFirewire',type: 'confirm', label: 'Disable Firewire?',                          default: true },
    { id: 'secureBoot',     type: 'confirm', label: 'Add security= GRUB boot params?',            default: false },
  ],

  generate({ options }) {
    const ptraceScope = options.ptraceScope    ?? '2';
    const apparmor    = options.apparmor       ?? true;
    const hidePid     = options.hidePid        ?? true;
    const noUsb       = options.disableUsb     ?? false;
    const noFirewire  = options.disableFirewire ?? true;
    const secureBoot  = options.secureBoot     ?? false;

    return `
# ── Kernel Hardening (openSUSE) ───────────────────────────────────────
${apparmor ? 'zypper install -y -n apparmor-utils apparmor-profiles' : ''}

cat > /etc/sysctl.d/99-sf-kernel.conf << 'EOF'
${SYSCTL_KERNEL.replace('kernel.yama.ptrace_scope = 2', `kernel.yama.ptrace_scope = ${ptraceScope}`)}
${SYSCTL_FS}
EOF
sysctl --system

${apparmor ? `
systemctl enable --now apparmor
# Enforce all profiles that are in complain mode
aa-enforce /etc/apparmor.d/* 2>/dev/null || true
` : ''}

${hidePid ? `
if ! grep -q 'hidepid' /etc/fstab; then
  echo 'proc /proc proc defaults,hidepid=2,gid=proc 0 0' >> /etc/fstab
fi
groupadd -f proc
` : ''}

cat > /etc/modprobe.d/sf-kernel.conf << 'MODS'
${noUsb      ? 'install usb_storage /bin/false\nblacklist usb_storage' : ''}
${noFirewire ? 'install firewire-core /bin/false\nblacklist firewire-core' : ''}
install cramfs   /bin/false
install freevxfs /bin/false
install jffs2    /bin/false
install hfs      /bin/false
install hfsplus  /bin/false
install udf      /bin/false
MODS

${secureBoot ? `
GRUB_FILE=/etc/default/grub
PARAMS="lockdown=confidentiality lsm=landlock,lockdown,yama,integrity,apparmor,bpf"
grep -q 'lockdown' "$GRUB_FILE" || \
  sed -i "s|GRUB_CMDLINE_LINUX=\\\"\\(.*\\)\\\"|GRUB_CMDLINE_LINUX=\\\"\\1 $PARAMS\\\"|" "$GRUB_FILE"
grub2-mkconfig -o /boot/grub2/grub.cfg 2>/dev/null || true
` : ''}
`;
  },

  manifests({ options }) {
    return {
      created: ['/etc/sysctl.d/99-sf-kernel.conf', '/etc/modprobe.d/sf-kernel.conf'],
      packages_installed: [...(options.apparmor ? ['apparmor-utils', 'apparmor-profiles'] : [])],
    };
  },
};
