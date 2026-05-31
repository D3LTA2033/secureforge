import { SYSCTL_KERNEL, SYSCTL_FS } from '../shared/sysctl.js';

export default {
  id: 'kernel',
  name: 'Kernel Hardening',
  description: 'ASLR, ptrace, BPF, SELinux enforcing, module blacklists',
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
    { id: 'selinux',        type: 'list',    label: 'SELinux mode:',
      choices: [
        { name: 'enforcing (recommended)',       value: 'enforcing' },
        { name: 'permissive (log only)',         value: 'permissive' },
        { name: 'keep current',                  value: 'keep' },
      ], default: 'enforcing' },
    { id: 'hidePid',        type: 'confirm', label: 'hidepid=2 on /proc?',                         default: true },
    { id: 'disableUsb',     type: 'confirm', label: 'Disable USB storage?',                        default: false },
    { id: 'disableFirewire',type: 'confirm', label: 'Disable Firewire (DMA vector)?',              default: true },
    { id: 'secureBoot',     type: 'confirm', label: 'Add security= GRUB boot params?',             default: false },
    { id: 'lockdownKernel', type: 'confirm', label: 'Kernel lockdown=confidentiality (UEFI)?',     default: false },
  ],

  generate({ options }) {
    const ptraceScope  = options.ptraceScope    ?? '2';
    const selinux      = options.selinux        ?? 'enforcing';
    const hidePid      = options.hidePid        ?? true;
    const noUsb        = options.disableUsb     ?? false;
    const noFirewire   = options.disableFirewire ?? true;
    const secureBoot   = options.secureBoot     ?? false;
    const lockdown     = options.lockdownKernel ?? false;

    return `
# ── Kernel Hardening (Fedora) ─────────────────────────────────────────

cat > /etc/sysctl.d/99-sf-kernel.conf << 'EOF'
${SYSCTL_KERNEL.replace('kernel.yama.ptrace_scope = 2', `kernel.yama.ptrace_scope = ${ptraceScope}`)}
${SYSCTL_FS}
EOF
sysctl --system

${selinux !== 'keep' ? `
# SELinux
sed -i 's/^SELINUX=.*/SELINUX=${selinux}/' /etc/selinux/config
setenforce ${selinux === 'enforcing' ? '1' : '0'} 2>/dev/null || true
dnf install -y policycoreutils policycoreutils-python-utils setools-console
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

${secureBoot || lockdown ? `
GRUB_FILE=/etc/default/grub
PARAMS="${lockdown ? 'lockdown=confidentiality' : ''} lsm=landlock,lockdown,yama,integrity,selinux,bpf"
grep -q 'lockdown' "$GRUB_FILE" || \
  sed -i "s|GRUB_CMDLINE_LINUX=\\\"\\(.*\\)\\\"|GRUB_CMDLINE_LINUX=\\\"\\1 $PARAMS\\\"|" "$GRUB_FILE"
grub2-mkconfig -o /boot/grub2/grub.cfg 2>/dev/null || grub2-mkconfig -o /boot/efi/EFI/fedora/grub.cfg 2>/dev/null || true
` : ''}
`;
  },

  manifests() {
    return {
      created: ['/etc/sysctl.d/99-sf-kernel.conf', '/etc/modprobe.d/sf-kernel.conf'],
    };
  },
};
