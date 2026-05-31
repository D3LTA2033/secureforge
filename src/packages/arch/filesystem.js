export default {
  id: 'filesystem',
  name: 'Filesystem Security',
  description: 'Mount hardening, /tmp noexec, sticky bits, world-writable scan, immutable dirs',
  category: 'Filesystem',
  defaultEnabled: true,

  options: [
    { id: 'hardenTmp',      type: 'confirm', label: 'Mount /tmp with noexec,nosuid,nodev?',           default: true },
    { id: 'hardenDev',      type: 'confirm', label: 'Mount /dev/shm with noexec,nosuid,nodev?',       default: true },
    { id: 'hardenVar',      type: 'confirm', label: 'Mount /var with nosuid,nodev?',                  default: false },
    { id: 'hardenHome',     type: 'confirm', label: 'Mount /home with nosuid,nodev?',                 default: false },
    { id: 'stickyBit',      type: 'confirm', label: 'Enforce sticky bit on world-writable dirs?',     default: true },
    { id: 'removeOthers',   type: 'confirm', label: 'Remove world-writeable perms from sensitive dirs?', default: true },
    { id: 'scanSuid',       type: 'confirm', label: 'List all SUID/SGID files to audit log?',         default: true },
    { id: 'immutableDirs',  type: 'confirm', label: 'Make /boot/grub immutable (chattr +i)?',         default: false },
    { id: 'noAutoMount',    type: 'confirm', label: 'Disable USB/media auto-mount?',                  default: false },
  ],

  generate({ options }) {
    const hardenTmp   = options.hardenTmp     ?? true;
    const hardenShm   = options.hardenDev     ?? true;
    const hardenVar   = options.hardenVar     ?? false;
    const hardenHome  = options.hardenHome    ?? false;
    const sticky      = options.stickyBit     ?? true;
    const removeOth   = options.removeOthers  ?? true;
    const scanSuid    = options.scanSuid      ?? true;
    const immutable   = options.immutableDirs ?? false;
    const noAutoMnt   = options.noAutoMount   ?? false;

    return `
# ── Filesystem Security (Arch) ────────────────────────────────────────

${hardenTmp ? `
# Harden /tmp
if grep -q 'tmpfs /tmp' /etc/fstab; then
  sed -i 's|tmpfs /tmp.*|tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime,size=512M 0 0|' /etc/fstab
else
  echo 'tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime,size=512M 0 0' >> /etc/fstab
fi
mount -o remount /tmp 2>/dev/null || true
` : ''}

${hardenShm ? `
# Harden /dev/shm
if grep -q '/dev/shm' /etc/fstab; then
  sed -i 's|.*/dev/shm.*|tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec,relatime 0 0|' /etc/fstab
else
  echo 'tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec,relatime 0 0' >> /etc/fstab
fi
mount -o remount /dev/shm 2>/dev/null || true
` : ''}

${hardenVar ? `
# Harden /var
if grep -qE '\\s+/var\\s+' /etc/fstab; then
  sed -i '/\\s\\/var\\s/s/defaults/defaults,nosuid,nodev/' /etc/fstab
fi
` : ''}

${hardenHome ? `
# Harden /home
if grep -qE '\\s+/home\\s+' /etc/fstab; then
  sed -i '/\\s\\/home\\s/s/defaults/defaults,nosuid,nodev/' /etc/fstab
fi
` : ''}

${sticky ? `
# Enforce sticky bit on world-writable directories
find / -xdev -type d -perm -0002 -not -perm -1000 2>/dev/null | while read -r dir; do
  chmod +t "$dir"
  echo "[+] Sticky bit set: $dir"
done
` : ''}

${removeOth ? `
# Remove world-write from sensitive system directories
for dir in /etc /usr /bin /sbin /usr/bin /usr/sbin; do
  find "$dir" -xdev -type f -perm -o+w 2>/dev/null | while read -r f; do
    chmod o-w "$f"
    echo "[!] Removed world-write: $f"
  done
done
` : ''}

${scanSuid ? `
# SUID/SGID audit
echo "=== SUID/SGID files found ===" >> /etc/secureforge/suid-audit.txt
find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null >> /etc/secureforge/suid-audit.txt
echo "[+] SUID audit saved to /etc/secureforge/suid-audit.txt"
` : ''}

${immutable ? `
# Make GRUB config immutable
chattr +i /boot/grub/grub.cfg 2>/dev/null || true
echo "[!] /boot/grub/grub.cfg made immutable. Run 'chattr -i /boot/grub/grub.cfg' to edit GRUB."
` : ''}

${noAutoMnt ? `
# Disable udisks2 automounting
systemctl disable --now udisks2 2>/dev/null || true
pacman -R --noconfirm udisks2 2>/dev/null || true
` : ''}

# Secure critical file permissions
chmod 600 /etc/shadow
chmod 644 /etc/passwd
chmod 644 /etc/group
chmod 600 /etc/gshadow
chmod 700 /root
chmod 755 /etc/cron.d/ /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.monthly/ 2>/dev/null || true
chmod 600 /etc/crontab 2>/dev/null || true

# Remove write perms from global cron dirs
chown root:root /etc/crontab /etc/cron.d/ 2>/dev/null || true
`;
  },

  manifests({ options }) {
    return {
      created: [
        ...(options.scanSuid ? ['/etc/secureforge/suid-audit.txt'] : []),
      ],
    };
  },
};
