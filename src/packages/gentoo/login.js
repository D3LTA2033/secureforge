export default {
  id: 'login',
  name: 'Login Security',
  description: 'PAM faillock, password quality, banner, session timeout, umask',
  category: 'Access Control',
  defaultEnabled: true,

  options: [
    { id: 'minPassLen',      type: 'input',   label: 'Minimum password length:',       default: '14' },
    { id: 'lockoutAttempts', type: 'input',   label: 'Lockout after N failed attempts:', default: '5' },
    { id: 'lockoutTime',     type: 'input',   label: 'Lockout duration (seconds):',     default: '900' },
    { id: 'loginBanner',     type: 'confirm', label: 'Set unauthorized-access banner?', default: true },
    { id: 'ctrlAltDel',      type: 'confirm', label: 'Disable Ctrl+Alt+Del reboot?',    default: true },
    { id: 'secureUmask',     type: 'confirm', label: 'Set secure umask (027)?',          default: true },
    { id: 'sessionTimeout',  type: 'input',   label: 'Auto-logout idle sessions (sec):', default: '900' },
  ],

  generate({ options }) {
    const minLen   = parseInt(options.minPassLen      ?? '14');
    const lockout  = parseInt(options.lockoutAttempts ?? '5');
    const lockTime = parseInt(options.lockoutTime     ?? '900');
    const banner   = options.loginBanner   ?? true;
    const umask    = options.secureUmask   ?? true;
    const timeout  = parseInt(options.sessionTimeout  ?? '900');

    return `
# ── Login Security (Gentoo) ───────────────────────────────────────────
# [ALPHA]
emerge --ask=n sys-libs/pam sys-auth/libpwquality

cat > /etc/security/pwquality.conf << 'PWQUAL'
minlen = ${minLen}
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
maxrepeat = 3
PWQUAL

cat > /etc/security/faillock.conf << 'FAIL'
deny = ${lockout}
unlock_time = ${lockTime}
fail_interval = 900
even_deny_root
root_unlock_time = 60
audit
FAIL

# PAM faillock injection (Gentoo uses /etc/pam.d/system-auth)
SYSAUTH=/etc/pam.d/system-auth
if ! grep -q 'pam_faillock' "$SYSAUTH" 2>/dev/null; then
  sed -i '0,/^auth/s//auth required pam_faillock.so preauth\nauth/' "$SYSAUTH" 2>/dev/null || true
fi

${banner ? `
cat > /etc/issue << 'BANNER'
*******************************************
*   UNAUTHORIZED ACCESS IS PROHIBITED    *
*   All sessions are logged and audited  *
*******************************************
BANNER
cat /etc/issue > /etc/issue.net
` : ''}

${umask ? `
cat > /etc/profile.d/sf-umask.sh << 'UMASK'
umask 027
UMASK
chmod 644 /etc/profile.d/sf-umask.sh
` : ''}

${timeout > 0 ? `
cat > /etc/profile.d/sf-timeout.sh << 'TIMEOUT'
TMOUT=${timeout}
readonly TMOUT
export TMOUT
TIMEOUT
chmod 644 /etc/profile.d/sf-timeout.sh
` : ''}

sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/'  /etc/login.defs 2>/dev/null || true
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/'   /etc/login.defs 2>/dev/null || true
echo '* hard core 0' >> /etc/security/limits.conf
`;
  },

  manifests() {
    return {
      created: ['/etc/security/pwquality.conf', '/etc/security/faillock.conf', '/etc/profile.d/sf-umask.sh'],
    };
  },
};
