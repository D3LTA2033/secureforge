export default {
  id: 'filesystem',
  name: 'Filesystem Security',
  description: 'Mount hardening, /tmp noexec, sticky bits, SUID audit, immutable dirs',
  category: 'Filesystem',
  defaultEnabled: true,

  options: [
    { id: 'hardenTmp',    type: 'confirm', label: 'Mount /tmp with noexec,nosuid,nodev?',       default: true },
    { id: 'hardenDev',    type: 'confirm', label: 'Mount /dev/shm with noexec,nosuid,nodev?',   default: true },
    { id: 'hardenVar',    type: 'confirm', label: 'Mount /var with nosuid,nodev?',              default: false },
    { id: 'hardenHome',   type: 'confirm', label: 'Mount /home with nosuid,nodev?',             default: false },
    { id: 'stickyBit',    type: 'confirm', label: 'Enforce sticky bit on world-writable dirs?', default: true },
    { id: 'removeOthers', type: 'confirm', label: 'Remove world-write from sensitive dirs?',    default: true },
    { id: 'scanSuid',     type: 'confirm', label: 'Audit SUID/SGID files?',                     default: true },
    { id: 'immutableBoot',type: 'confirm', label: 'Make /boot immutable (chattr +i)?',          default: false },
    { id: 'aptHarden',    type: 'confirm', label: 'Harden apt/dpkg security settings?',         default: true },
  ],

  generate({ options }) {
    const hardenTmp  = options.hardenTmp    ?? true;
    const hardenShm  = options.hardenDev    ?? true;
    const hardenVar  = options.hardenVar    ?? false;
    const hardenHome = options.hardenHome   ?? false;
    const sticky     = options.stickyBit    ?? true;
    const removeOth  = options.removeOthers ?? true;
    const scanSuid   = options.scanSuid     ?? true;
    const immutable  = options.immutableBoot?? false;
    const aptHarden  = options.aptHarden    ?? true;

    return `
# ── Filesystem Security (Debian) ─────────────────────────────────────

${hardenTmp ? `
if grep -q 'tmpfs /tmp' /etc/fstab; then
  sed -i 's|tmpfs /tmp.*|tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime,size=512M 0 0|' /etc/fstab
else
  echo 'tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime,size=512M 0 0' >> /etc/fstab
fi
mount -o remount /tmp 2>/dev/null || true
` : ''}

${hardenShm ? `
if grep -q '/dev/shm' /etc/fstab; then
  sed -i 's|.*/dev/shm.*|tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec,relatime 0 0|' /etc/fstab
else
  echo 'tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec,relatime 0 0' >> /etc/fstab
fi
mount -o remount /dev/shm 2>/dev/null || true
` : ''}

${hardenVar ? `
if grep -qE '\\s+/var\\s+' /etc/fstab; then
  sed -i '/\\s\\/var\\s/s/defaults/defaults,nosuid,nodev/' /etc/fstab
fi
` : ''}

${hardenHome ? `
if grep -qE '\\s+/home\\s+' /etc/fstab; then
  sed -i '/\\s\\/home\\s/s/defaults/defaults,nosuid,nodev/' /etc/fstab
fi
` : ''}

${sticky ? `
find / -xdev -type d -perm -0002 -not -perm -1000 2>/dev/null | while read -r dir; do
  chmod +t "$dir"
done
` : ''}

${removeOth ? `
for dir in /etc /usr /bin /sbin /usr/bin /usr/sbin; do
  find "$dir" -xdev -type f -perm -o+w 2>/dev/null | while read -r f; do
    chmod o-w "$f"
  done
done
` : ''}

${scanSuid ? `
echo "=== SUID/SGID files ===" >> /etc/secureforge/suid-audit.txt
find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null >> /etc/secureforge/suid-audit.txt
` : ''}

${immutable ? `
chattr +i /boot/grub/grub.cfg 2>/dev/null || true
` : ''}

${aptHarden ? `
# Prevent apt from running scripts as root silently
cat > /etc/apt/apt.conf.d/99-sf-harden << 'APTHARDEN'
APT::Get::AllowUnauthenticated "false";
Acquire::AllowInsecureRepositories "false";
Acquire::AllowDowngradeToInsecureRepositories "false";
APTHARDEN
` : ''}

# Fix permissions on critical files
chmod 600 /etc/shadow /etc/gshadow 2>/dev/null || true
chmod 644 /etc/passwd /etc/group   2>/dev/null || true
chmod 700 /root
chmod 600 /etc/crontab 2>/dev/null || true
echo '* hard core 0' >> /etc/security/limits.conf
`;
  },

  manifests({ options }) {
    return {
      created: [
        ...(options.aptHarden ? ['/etc/apt/apt.conf.d/99-sf-harden'] : []),
        ...(options.scanSuid  ? ['/etc/secureforge/suid-audit.txt']  : []),
      ],
    };
  },
};
