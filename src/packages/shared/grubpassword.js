export default {
  id: 'grubpassword',
  name: 'GRUB Bootloader Password',
  description: 'Protect bootloader with a superuser password — prevents single-user / recovery boot',
  category: 'Boot Security',
  defaultEnabled: false,

  options: [
    { id: 'grubUser',     type: 'input',   label: 'GRUB superuser username:',                              default: 'grubadmin',
      validate: v => /^[a-z_][a-z0-9_-]{1,31}$/.test(v) || 'Invalid username' },
    { id: 'grubPassword', type: 'input',   label: 'GRUB password (plain — will be hashed with grub-crypt):', default: '',
      validate: v => v.length >= 8 || 'Min 8 characters' },
    { id: 'unrestricted', type: 'confirm', label: 'Allow booting default entry without password (only protect edit/recovery)?', default: true },
  ],

  generate({ distro, options }) {
    const grubUser     = options.grubUser     ?? 'grubadmin';
    const grubPassword = options.grubPassword ?? '';
    const unrestricted = options.unrestricted ?? true;

    if (!grubPassword) return '# GRUB password: no password set, skipping.';

    // Determine grub-mkconfig path per distro
    const grubMkconfigCmd = ['arch'].includes(distro)
      ? 'grub-mkconfig -o /boot/grub/grub.cfg'
      : 'grub2-mkconfig -o /boot/grub2/grub.cfg 2>/dev/null || grub-mkconfig -o /boot/grub/grub.cfg 2>/dev/null || update-grub 2>/dev/null || true';

    const grubCryptCmd = ['arch'].includes(distro)
      ? 'grub-mkpasswd-pbkdf2'
      : 'grub2-mkpasswd-pbkdf2 2>/dev/null || grub-mkpasswd-pbkdf2';

    return `
# ── GRUB Bootloader Password (${distro}) ──────────────────────────────
#
# Generates a PBKDF2 password hash and writes a GRUB superuser config.
# The superuser '${grubUser}' is required to edit boot entries or access recovery.
${unrestricted ? `# Normal boot entries remain unrestricted (--unrestricted flag).` : `# ALL boot entries require the password.`}

# Generate PBKDF2 hash from the password
GRUB_HASH=$(echo -e '${grubPassword}\\n${grubPassword}' | ${grubCryptCmd} 2>/dev/null | grep 'grub.pbkdf2' | awk '{print $NF}')

if [ -z "$GRUB_HASH" ]; then
  echo "[!] Could not generate GRUB hash — grub-mkpasswd-pbkdf2 not found."
  echo "[!] Install grub2-tools or grub package first."
  exit 1
fi

# Write GRUB superuser config
cat > /etc/grub.d/01_secureforge_password << GRUBSCRIPT
#!/bin/sh
set -e

cat << EOF
set superusers="${grubUser}"
password_pbkdf2 ${grubUser} \$GRUB_HASH
EOF
GRUBSCRIPT

chmod 700 /etc/grub.d/01_secureforge_password

${unrestricted ? `
# Make default menu entries unrestricted (require password only for edit/recovery)
# Patch 10_linux to add --unrestricted flag
LINUX_SCRIPT=/etc/grub.d/10_linux
[ -f "$LINUX_SCRIPT" ] && ! grep -q 'unrestricted' "$LINUX_SCRIPT" && \
  sed -i "s/--class gnu-linux/--class gnu-linux --unrestricted/" "$LINUX_SCRIPT" || true
` : ''}

# Rebuild GRUB config
${grubMkconfigCmd}

# Protect GRUB config file
chmod 600 /boot/grub/grub.cfg  2>/dev/null || true
chmod 600 /boot/grub2/grub.cfg 2>/dev/null || true

echo "[+] GRUB password set for superuser '${grubUser}'."
echo "[!] Keep this password safe — losing it requires live USB recovery to remove."
`;
  },

  manifests() {
    return {
      created: ['/etc/grub.d/01_secureforge_password'],
    };
  },
};
