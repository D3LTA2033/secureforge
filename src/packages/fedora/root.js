export default {
  id: 'root',
  name: 'Root Account Security',
  description: 'Lock root, sudo hardening, su via wheel, SELinux sudo rules',
  category: 'Access Control',
  defaultEnabled: true,

  options: [
    { id: 'lockRoot',      type: 'confirm', label: 'Lock root account?',                          default: true },
    { id: 'sudoTimeout',   type: 'input',   label: 'sudo session timeout (minutes):',              default: '5',
      validate: v => parseInt(v) >= 0 || 'Must be >= 0' },
    { id: 'sudoLogging',   type: 'confirm', label: 'Log all sudo commands?',                       default: true },
    { id: 'noSuNonWheel',  type: 'confirm', label: 'Block su for non-wheel users?',                default: true },
    { id: 'rootShell',     type: 'list',    label: 'Root shell:', default: 'keep',
      choices: [
        { name: 'Keep current',        value: 'keep' },
        { name: '/sbin/nologin',       value: '/sbin/nologin' },
        { name: '/bin/false',          value: '/bin/false' },
      ]
    },
  ],

  generate({ options }) {
    const lockRoot  = options.lockRoot      ?? true;
    const timeout   = parseInt(options.sudoTimeout  ?? '5');
    const logging   = options.sudoLogging   ?? true;
    const noSu      = options.noSuNonWheel  ?? true;
    const rootShell = options.rootShell     ?? 'keep';

    return `
# ── Root Account Security (Fedora) ───────────────────────────────────
dnf install -y sudo

${lockRoot ? `passwd -l root` : ''}
${rootShell !== 'keep' ? `usermod -s ${rootShell} root` : ''}

mkdir -p /etc/sudoers.d
cat > /etc/sudoers.d/99-secureforge << 'SUDO'
Defaults  env_reset
Defaults  secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults  timestamp_timeout=${timeout}
Defaults  badpass_message="Access denied."
Defaults  passwd_tries=3
${logging ? `Defaults  logfile="/var/log/sudo.log"\nDefaults  log_input,log_output` : ''}
Defaults  requiretty
Defaults  !visiblepw

%wheel ALL=(ALL:ALL) ALL
SUDO
chmod 440 /etc/sudoers.d/99-secureforge
visudo -c -f /etc/sudoers.d/99-secureforge

${noSu ? `
cat > /etc/pam.d/su << 'SUCONF'
auth       sufficient  pam_rootok.so
auth       required    pam_wheel.so use_uid
auth       include     system-auth
account    include     system-auth
session    include     system-auth
SUCONF
` : ''}

${logging ? 'touch /var/log/sudo.log && chmod 600 /var/log/sudo.log' : ''}

chmod 700 /root
chmod 700 /root/.ssh 2>/dev/null || true
`;
  },

  manifests({ options }) {
    return {
      created: ['/etc/sudoers.d/99-secureforge'],
      packages_installed: ['sudo'],
    };
  },
};
