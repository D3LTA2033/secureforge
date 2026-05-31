import { SYSCTL_KERNEL, SYSCTL_FS } from '../shared/sysctl.js';

export default {
  id: 'kernel',
  name: 'Kernel Hardening',
  description: 'ASLR, ptrace, BPF, dmesg, perf restrictions, secure boot params',
  category: 'Kernel',
  defaultEnabled: true,

  options: [
    { id: 'aslr',          type: 'confirm', label: 'ASLR (randomize_va_space=2)?',            default: true },
    { id: 'ptraceScope',   type: 'list',    label: 'ptrace scope:',
      choices: [
        { name: '0 — no restriction',                  value: '0' },
        { name: '1 — restrict to child processes',     value: '1' },
        { name: '2 — admin only (recommended)',         value: '2' },
        { name: '3 — fully disabled',                  value: '3' },
      ], default: '2' },
    { id: 'hidePid',       type: 'confirm', label: 'Hide other users\' processes (/proc hidepid=2)?', default: true },
    { id: 'lockdownKernel',type: 'confirm', label: 'Lock kernel modules after boot (modules_disabled)?', default: false },
    { id: 'secureBoot',    type: 'confirm', label: 'Add security= GRUB boot params?',           default: false },
    { id: 'disableUsb',    type: 'confirm', label: 'Disable USB storage (usb_storage module)?', default: false },
    { id: 'disableFirewire',type:'confirm', label: 'Disable Firewire (DMA attack vector)?',     default: true },
    { id: 'disableThunderbolt',type:'confirm',label:'Disable Thunderbolt DMA?',                 default: false },
  ],

  generate({ options }) {
    const ptraceScope = options.ptraceScope ?? '2';
    const hidePid     = options.hidePid     ?? true;
    const lockMods    = options.lockdownKernel ?? false;
    const secureBoot  = options.secureBoot  ?? false;
    const noUsb       = options.disableUsb  ?? false;
    const noFirewire  = options.disableFirewire ?? true;
    const noTb        = options.disableThunderbolt ?? false;

    return `
# ── Kernel Hardening (Arch) ──────────────────────────────────────────

cat > /etc/sysctl.d/99-sf-kernel.conf << 'EOF'
${SYSCTL_KERNEL.replace('kernel.yama.ptrace_scope = 2', `kernel.yama.ptrace_scope = ${ptraceScope}`)}
${SYSCTL_FS}
EOF

sysctl --system --load /etc/sysctl.d/99-sf-kernel.conf

${hidePid ? `
# Hide other users' processes in /proc
if ! grep -q 'hidepid' /etc/fstab; then
  echo 'proc /proc proc defaults,hidepid=2,gid=proc 0 0' >> /etc/fstab
fi
groupadd -f proc
# Add admins to proc group so they can still see processes
getent passwd | awk -F: '$3>=1000 && $3<65534 {print $1}' | head -3 | \
  xargs -I{} usermod -aG proc {} 2>/dev/null || true
` : ''}

# Module blacklisting
cat > /etc/modprobe.d/sf-kernel.conf << 'MODS'
${noUsb      ? 'install usb_storage /bin/false\nblacklist usb_storage' : ''}
${noFirewire ? 'install firewire-core /bin/false\nblacklist firewire-core\ninstall thunderbolt /bin/false' : ''}
${noTb       ? 'install thunderbolt /bin/false\nblacklist thunderbolt' : ''}
# Disable uncommon filesystems
install cramfs   /bin/false
install freevxfs /bin/false
install jffs2    /bin/false
install hfs      /bin/false
install hfsplus  /bin/false
install squashfs /bin/false
install udf      /bin/false
MODS

${secureBoot ? `
# Secure boot parameters in GRUB
GRUB_FILE=/etc/default/grub
PARAMS="lockdown=confidentiality lsm=landlock,lockdown,yama,integrity,apparmor,bpf"
if grep -q 'GRUB_CMDLINE_LINUX=' "$GRUB_FILE"; then
  sed -i "s|GRUB_CMDLINE_LINUX=\\\"\\(.*\\)\\\"|GRUB_CMDLINE_LINUX=\\\"\\1 $PARAMS\\\"|" "$GRUB_FILE"
fi
grub-mkconfig -o /boot/grub/grub.cfg 2>/dev/null || true
` : ''}

${lockMods ? `
# Lock kernel module loading after boot (irreversible until reboot)
echo 1 > /proc/sys/kernel/modules_disabled || true
` : ''}
`;
  },

  manifests() {
    return {
      created: ['/etc/sysctl.d/99-sf-kernel.conf', '/etc/modprobe.d/sf-kernel.conf'],
    };
  },
};
