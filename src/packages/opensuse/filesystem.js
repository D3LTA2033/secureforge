export default {
  id: 'filesystem',
  name: 'Filesystem Security',
  description: 'Mount hardening, /tmp noexec, sticky bits, SUID audit, zypper repo hardening',
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
    { id: 'immutableBoot',type: 'confirm', label: 'Make /boot/grub2 immutable?',                default: false },
    { id: 'zypperHarden', type: 'confirm', label: 'Harden zypper repo GPG enforcement?',        default: true },
  ],

  generate({ options }) {
    const hardenTmp  = options.hardenTmp    ?? true;
    const hardenShm  = options.hardenDev    ?? true;
    const hardenVar  = options.hardenVar    ?? false;
    const hardenHome = options.hardenHome   ?? false;
    const sticky     = options.stickyBit    ?? true;
    const removeOth  = options.removeOthers ?? true;
    const scanSuid   = options.scanSuid     ?? true;
    const immutable  = options.immutableBoot ?? false;
    const zypperH    = options.zypperHarden ?? true;

    return `
# ── Filesystem Security (openSUSE) ────────────────────────────────────

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

${hardenVar ? `grep -qE '\\s+/var\\s+' /etc/fstab && sed -i '/\\s\\/var\\s/s/defaults/defaults,nosuid,nodev/' /etc/fstab` : ''}

${hardenHome ? `grep -qE '\\s+/home\\s+' /etc/fstab && sed -i '/\\s\\/home\\s/s/defaults/defaults,nosuid,nodev/' /etc/fstab` : ''}

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

${immutable ? `chattr +i /boot/grub2/grub.cfg 2>/dev/null || true` : ''}

${zypperH ? `
# Enforce GPG checks in all zypper repos
for repo_file in /etc/zypp/repos.d/*.repo; do
  sed -i 's/^gpgcheck=.*/gpgcheck=1/' "$repo_file"
  sed -i 's/^autorefresh=.*/autorefresh=1/' "$repo_file"
done
` : ''}

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
        ...(options.scanSuid ? ['/etc/secureforge/suid-audit.txt'] : []),
      ],
    };
  },
};
