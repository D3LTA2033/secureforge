export default {
  id: 'filesystem',
  name: 'Filesystem Security',
  description: '/tmp noexec, sticky bits, SUID audit, portage package integrity',
  category: 'Filesystem',
  defaultEnabled: true,

  options: [
    { id: 'hardenTmp',       type: 'confirm', label: 'Mount /tmp with noexec,nosuid,nodev?',   default: true },
    { id: 'hardenShm',       type: 'confirm', label: 'Mount /dev/shm with noexec,nosuid?',     default: true },
    { id: 'stickyBit',       type: 'confirm', label: 'Enforce sticky bit on world-writable?',  default: true },
    { id: 'scanSuid',        type: 'confirm', label: 'Audit SUID/SGID files?',                 default: true },
    { id: 'portageVerify',   type: 'confirm', label: 'Verify installed packages with qcheck?', default: true },
  ],

  generate({ options }) {
    const hardenTmp  = options.hardenTmp    ?? true;
    const hardenShm  = options.hardenShm    ?? true;
    const sticky     = options.stickyBit    ?? true;
    const scanSuid   = options.scanSuid     ?? true;
    const portageV   = options.portageVerify ?? true;

    return `
# ── Filesystem Security (Gentoo) ─────────────────────────────────────
# [ALPHA]
${portageV ? `
emerge --ask=n app-portage/portage-utils
echo "[i] Checking package integrity..."
qcheck 2>/dev/null | grep -v '^OK' | head -20 | tee /etc/secureforge/portage-check.txt || true
` : ''}

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

${sticky ? `
find / -xdev -type d -perm -0002 -not -perm -1000 2>/dev/null | while read -r dir; do
  chmod +t "$dir"
done
` : ''}

${scanSuid ? `
echo "=== SUID/SGID files ===" > /etc/secureforge/suid-audit.txt
find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null >> /etc/secureforge/suid-audit.txt
` : ''}

chmod 600 /etc/shadow /etc/gshadow 2>/dev/null || true
chmod 644 /etc/passwd /etc/group   2>/dev/null || true
chmod 700 /root
echo '* hard core 0' >> /etc/security/limits.conf
`;
  },

  manifests() {
    return { created: ['/etc/secureforge/suid-audit.txt'] };
  },
};
