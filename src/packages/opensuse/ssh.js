import { sshConfig, SSH_BANNER, TOTP_PAM_LINE } from '../shared/ssh-config.js';

export default {
  id: 'ssh',
  name: 'SSH Lockdown',
  description: 'Harden SSH: key-only auth, ciphers, 2FA, port knocking',
  category: 'Access Control',
  defaultEnabled: true,

  options: [
    { id: 'disablePasswordAuth', type: 'confirm', label: 'Disable password auth (keys only)?',        default: true },
    { id: 'disableRootLogin',    type: 'confirm', label: 'Disable root login?',                       default: true },
    { id: 'changePort',          type: 'confirm', label: 'Change SSH port (from 22)?',                 default: false },
    { id: 'customPort',          type: 'input',   label: 'SSH port number:',                           default: '2222',
      validate: v => (parseInt(v) > 1024 && parseInt(v) < 65535) || 'Use port 1025–65534' },
    { id: 'totp',                type: 'confirm', label: 'Enable TOTP 2FA (google-authenticator)?',    default: false },
    { id: 'portKnocking',        type: 'confirm', label: 'Enable port knocking (knockd)?',             default: false },
    { id: 'allowUsers',          type: 'input',   label: 'Restrict SSH to users (space-separated):',   default: '' },
  ],

  generate({ options }) {
    const port       = options.changePort ? (parseInt(options.customPort) || 2222) : 22;
    const allowUsers = options.allowUsers?.trim().split(/\s+/).filter(Boolean) ?? [];
    const totp       = options.totp ?? false;
    const knocking   = options.portKnocking ?? false;
    const cfg        = sshConfig({ port, allowUsers, totp });

    return `
# ── SSH Lockdown (openSUSE) ───────────────────────────────────────────
zypper install -y -n openssh \
  ${totp    ? 'google-authenticator-libpam' : ''} \
  ${knocking ? 'knockd' : ''}

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

${totp ? `
if ! grep -q 'pam_google_authenticator' /etc/pam.d/sshd; then
  echo '${TOTP_PAM_LINE}' >> /etc/pam.d/sshd
fi
` : ''}

${knocking ? `
cat > /etc/knockd.conf << 'KNOCK'
[options]
  UseSyslog
[openSSH]
  sequence    = 7000,8000,9000
  seq_timeout = 10
  command     = /usr/bin/firewall-cmd --add-rich-rule="rule family=ipv4 source address=%IP% port port=${port} protocol=tcp accept"
  tcpflags    = syn
[closeSSH]
  sequence    = 9000,8000,7000
  seq_timeout = 10
  command     = /usr/bin/firewall-cmd --remove-rich-rule="rule family=ipv4 source address=%IP% port port=${port} protocol=tcp accept"
  tcpflags    = syn
KNOCK
systemctl enable --now knockd
` : ''}

systemctl enable --now sshd
systemctl restart sshd

cat > /etc/ssh/ssh_config.d/99-secureforge.conf << 'CLIENTEOF'
Host *
    HashKnownHosts yes
    PasswordAuthentication no
    ChallengeResponseAuthentication no
    GSSAPIAuthentication no
    StrictHostKeyChecking ask
    ServerAliveInterval 60
    ServerAliveCountMax 3
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
    MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
CLIENTEOF
`;
  },

  manifests() {
    return {
      backups:  [{ original: '/etc/ssh/sshd_config', backup: '/etc/ssh/sshd_config.sf.bak' }],
      created:  ['/etc/ssh/sshd_config.d/99-secureforge.conf'],
      packages_installed: ['openssh'],
    };
  },
};
