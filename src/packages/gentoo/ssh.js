import { sshConfig, SSH_BANNER } from '../shared/ssh-config.js';

export default {
  id: 'ssh',
  name: 'SSH Lockdown',
  description: 'Harden SSH: key-only, strong ciphers, USE flag hardening, OpenRC restart',
  category: 'Access Control',
  defaultEnabled: true,

  options: [
    { id: 'disablePasswordAuth', type: 'confirm', label: 'Disable password auth?',                   default: true },
    { id: 'disableRootLogin',    type: 'confirm', label: 'Disable root login?',                      default: true },
    { id: 'changePort',          type: 'confirm', label: 'Change SSH port?',                          default: false },
    { id: 'customPort',          type: 'input',   label: 'SSH port:',                                 default: '2222',
      validate: v => (parseInt(v) > 1024 && parseInt(v) < 65535) || 'Use port 1025–65534' },
    { id: 'paxHarden',           type: 'confirm', label: 'Apply PaX/SSP USE flags to openssh?',       default: true },
    { id: 'allowUsers',          type: 'input',   label: 'Restrict SSH to users (space-separated):',  default: '' },
  ],

  generate({ options }) {
    const port       = options.changePort ? (parseInt(options.customPort) || 2222) : 22;
    const allowUsers = options.allowUsers?.trim().split(/\s+/).filter(Boolean) ?? [];
    const pax        = options.paxHarden ?? true;
    const cfg        = sshConfig({ port, allowUsers, totp: false });

    return `
# ── SSH Lockdown (Gentoo) ─────────────────────────────────────────────
# [ALPHA] Gentoo-specific SSH hardening with Portage USE flags

${pax ? `
# Add hardening USE flags to openssh
mkdir -p /etc/portage/package.use
grep -q 'net-misc/openssh' /etc/portage/package.use/sf-ssh 2>/dev/null || \
  echo 'net-misc/openssh pam ssl -X509 -ldap' > /etc/portage/package.use/sf-ssh
` : ''}

emerge --ask=n net-misc/openssh

mkdir -p /etc/ssh/sshd_config.d

[ -f /etc/ssh/sshd_config ] && cp /etc/ssh/sshd_config /etc/ssh/sshd_config.sf.bak

cat > /etc/ssh/sshd_config.d/99-secureforge.conf << 'SSHEOF'
${cfg}
SSHEOF
chmod 600 /etc/ssh/sshd_config.d/99-secureforge.conf

grep -q 'Include /etc/ssh/sshd_config.d' /etc/ssh/sshd_config || \
  echo 'Include /etc/ssh/sshd_config.d/*.conf' >> /etc/ssh/sshd_config

cat > /etc/issue.net << 'BANNER'
${SSH_BANNER}
BANNER

# OpenRC — restart sshd
rc-service sshd restart 2>/dev/null || true
rc-update add sshd default

cat > /etc/ssh/ssh_config.d/99-secureforge.conf << 'CLIENTEOF'
Host *
    HashKnownHosts yes
    PasswordAuthentication no
    StrictHostKeyChecking ask
    ServerAliveInterval 60
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
    MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
CLIENTEOF
`;
  },

  manifests() {
    return {
      backups:  [{ original: '/etc/ssh/sshd_config', backup: '/etc/ssh/sshd_config.sf.bak' }],
      created:  ['/etc/ssh/sshd_config.d/99-secureforge.conf'],
      packages_installed: ['net-misc/openssh'],
    };
  },
};
