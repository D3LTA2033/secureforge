export default {
  id: 'root',
  name: 'Root Account Security',
  description: 'Lock root, sudo hardening, su restriction, wheel group (Alpine/BusyBox)',
  category: 'Access Control',
  defaultEnabled: true,

  options: [
    { id: 'lockRoot',     type: 'confirm', label: 'Lock root account?',              default: true },
    { id: 'sudoTimeout',  type: 'input',   label: 'sudo timeout (minutes):',         default: '5' },
    { id: 'sudoLogging',  type: 'confirm', label: 'Log all sudo commands?',          default: true },
    { id: 'noSuNonWheel', type: 'confirm', label: 'Block su for non-wheel users?',   default: true },
  ],

  generate({ options }) {
    const lockRoot = options.lockRoot     ?? true;
    const timeout  = parseInt(options.sudoTimeout ?? '5');
    const logging  = options.sudoLogging  ?? true;
    const noSu     = options.noSuNonWheel ?? true;

    return `
# ── Root Account Security (Alpine) ───────────────────────────────────
# [ALPHA] Alpine uses BusyBox — some tools behave differently.
apk add --no-cache sudo shadow

${lockRoot ? `
# Lock root password (allow sudo escalation only)
passwd -l root 2>/dev/null || usermod -L root 2>/dev/null || true
` : ''}

mkdir -p /etc/sudoers.d
cat > /etc/sudoers.d/99-secureforge << 'SUDO'
Defaults  env_reset
Defaults  secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults  timestamp_timeout=${timeout}
Defaults  badpass_message="Access denied."
Defaults  passwd_tries=3
${logging ? `Defaults  logfile="/var/log/sudo.log"\nDefaults  log_input,log_output` : ''}
Defaults  !visiblepw
%wheel ALL=(ALL:ALL) ALL
SUDO
chmod 440 /etc/sudoers.d/99-secureforge
visudo -c -f /etc/sudoers.d/99-secureforge

${noSu ? `
# Restrict su to wheel group
if [ -f /etc/pam.d/su ]; then
  grep -q 'pam_wheel' /etc/pam.d/su || \
    echo 'auth required pam_wheel.so use_uid' >> /etc/pam.d/su
fi
` : ''}

${logging ? 'touch /var/log/sudo.log && chmod 600 /var/log/sudo.log' : ''}
chmod 700 /root
`;
  },

  manifests() {
    return { created: ['/etc/sudoers.d/99-secureforge'], packages_installed: ['sudo'] };
  },
};
