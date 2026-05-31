export default {
  id: 'root',
  name: 'Root Account Security',
  description: 'Lock root, restrict su, sudo hardening, wheel group enforcement',
  category: 'Access Control',
  defaultEnabled: true,

  options: [
    { id: 'lockRoot',         type: 'confirm', label: 'Lock root account (disable direct root login)?', default: true },
    { id: 'requireWheel',     type: 'confirm', label: 'Restrict sudo to wheel group only?',             default: true },
    { id: 'sudoTimeout',      type: 'input',   label: 'sudo session timeout (minutes):',                default: '5',
      validate: v => (parseInt(v) >= 0 && parseInt(v) <= 60) || '0–60' },
    { id: 'sudoLogging',      type: 'confirm', label: 'Log all sudo commands to syslog?',               default: true },
    { id: 'sudoEnvReset',     type: 'confirm', label: 'sudo env_reset (clean env on elevation)?',       default: true },
    { id: 'noSuNonWheel',     type: 'confirm', label: 'Block su for non-wheel users via PAM?',          default: true },
    { id: 'rootShell',        type: 'list',    label: 'Root shell (restrict to nologin to block direct root shells):', default: 'keep',
      choices: [
        { name: 'Keep current shell',             value: 'keep' },
        { name: '/sbin/nologin (recommended)',    value: '/sbin/nologin' },
        { name: '/bin/false',                     value: '/bin/false' },
      ]
    },
  ],

  generate({ options }) {
    const lockRoot    = options.lockRoot      ?? true;
    const wheel       = options.requireWheel  ?? true;
    const timeout     = parseInt(options.sudoTimeout   ?? '5');
    const logging     = options.sudoLogging   ?? true;
    const envReset    = options.sudoEnvReset  ?? true;
    const noSu        = options.noSuNonWheel  ?? true;
    const rootShell   = options.rootShell     ?? 'keep';

    return `
# ── Root Account Security (Arch) ─────────────────────────────────────
pacman -S --noconfirm --needed sudo

${lockRoot ? `
# Lock root account (password login disabled, root still usable via sudo)
passwd -l root
` : ''}

${rootShell !== 'keep' ? `
# Restrict root shell
usermod -s ${rootShell} root
` : ''}

# Sudoers hardening
mkdir -p /etc/sudoers.d

cat > /etc/sudoers.d/99-secureforge << 'SUDO'
# SecureForge sudoers hardening
Defaults  ${envReset ? 'env_reset' : ''}
Defaults  secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults  timestamp_timeout=${timeout}
Defaults  badpass_message="Access denied."
Defaults  passwd_tries=3
Defaults  ${logging ? 'logfile="/var/log/sudo.log"\nDefaults  log_input,log_output' : ''}
Defaults  requiretty
Defaults  umask=0022
Defaults  umask_override

${wheel ? `
# Only wheel group can use sudo
%wheel  ALL=(ALL:ALL) ALL
` : `
# Wheel group has sudo (add users: usermod -aG wheel username)
%wheel  ALL=(ALL:ALL) ALL
`}

# Disable dangerous sudo abilities
Defaults  !visiblepw
SUDO

chmod 440 /etc/sudoers.d/99-secureforge

# Validate sudoers file
visudo -c -f /etc/sudoers.d/99-secureforge

${noSu ? `
# Block su for non-wheel/root users via PAM
cat > /etc/pam.d/su << 'SUCONF'
auth       sufficient  pam_rootok.so
auth       required    pam_wheel.so use_uid
auth       required    pam_unix.so
account    required    pam_unix.so
session    required    pam_unix.so
SUCONF
` : ''}

${wheel ? `
# Ensure root is not in wheel (belt-and-suspenders)
gpasswd -d root wheel 2>/dev/null || true
` : ''}

# Ensure sudo log dir exists
${logging ? 'mkdir -p /var/log && touch /var/log/sudo.log && chmod 600 /var/log/sudo.log' : ''}

# /root permissions
chmod 700 /root
chmod 700 /root/.ssh 2>/dev/null || true
`;
  },

  manifests({ options }) {
    const logging = options.sudoLogging ?? true;
    return {
      created: [
        '/etc/sudoers.d/99-secureforge',
        ...(logging ? ['/var/log/sudo.log'] : []),
      ],
      packages_installed: ['sudo'],
    };
  },
};
