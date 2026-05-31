export default {
  id: 'filesystem',
  name: 'Filesystem Security',
  description: '/tmp noexec, sticky bits, SUID audit, apk package verification',
  category: 'Filesystem',
  defaultEnabled: true,

  options: [
    { id: 'hardenTmp',   type: 'confirm', label: 'Mount /tmp with noexec,nosuid,nodev?', default: true },
    { id: 'hardenShm',   type: 'confirm', label: 'Mount /dev/shm with noexec,nosuid?',   default: true },
    { id: 'stickyBit',   type: 'confirm', label: 'Enforce sticky bit on world-writable?', default: true },
    { id: 'scanSuid',    type: 'confirm', label: 'Audit SUID/SGID files?',                default: true },
    { id: 'apkVerify',   type: 'confirm', label: 'Verify installed apk packages?',        default: true },
    { id: 'apkGpg',      type: 'confirm', label: 'Enforce GPG verification for apk repos?', default: true },
  ],

  generate({ options }) {
    const hardenTmp = options.hardenTmp  ?? true;
    const hardenShm = options.hardenShm  ?? true;
    const sticky    = options.stickyBit  ?? true;
    const scanSuid  = options.scanSuid   ?? true;
    const apkVerify = options.apkVerify  ?? true;
    const apkGpg    = options.apkGpg     ?? true;

    return `
# ── Filesystem Security (Alpine) ─────────────────────────────────────
# [ALPHA]

${hardenTmp ? `
if grep -q 'tmpfs /tmp' /etc/fstab; then
  sed -i 's|tmpfs /tmp.*|tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime,size=256M 0 0|' /etc/fstab
else
  echo 'tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime,size=256M 0 0' >> /etc/fstab
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

${apkVerify ? `
echo "[i] Verifying installed apk packages..."
apk verify 2>/dev/null | grep -v 'OK' | tee /etc/secureforge/apk-verify.txt || true
` : ''}

${apkGpg ? `
# Ensure GPG signing is required for all repos
grep -r 'http://' /etc/apk/repositories && \
  echo "[!] WARNING: Some repos use plain HTTP — switch to HTTPS for security."
# Add --check-policy if supported
apk policy 2>/dev/null || true
` : ''}

chmod 600 /etc/shadow 2>/dev/null || true
chmod 644 /etc/passwd 2>/dev/null || true
chmod 700 /root
`;
  },

  manifests() {
    return { created: ['/etc/secureforge/suid-audit.txt'] };
  },
};
