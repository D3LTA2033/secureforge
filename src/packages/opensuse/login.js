export default {
  id: 'login',
  name: 'Login Security',
  description: 'PAM faillock, pam_pwquality, login banner, session timeout, pam_tally2',
  category: 'Access Control',
  defaultEnabled: true,

  options: [
    { id: 'minPassLen',      type: 'input',   label: 'Minimum password length:',                  default: '14',
      validate: v => parseInt(v) >= 8 || 'Min 8' },
    { id: 'lockoutAttempts', type: 'input',   label: 'Lockout after N failed attempts:',          default: '5' },
    { id: 'lockoutTime',     type: 'input',   label: 'Lockout duration (seconds):',               default: '900' },
    { id: 'loginBanner',     type: 'confirm', label: 'Set unauthorized-access login banner?',     default: true },
    { id: 'ctrlAltDel',      type: 'confirm', label: 'Disable Ctrl+Alt+Del reboot?',              default: true },
    { id: 'secureUmask',     type: 'confirm', label: 'Set secure umask (027)?',                   default: true },
    { id: 'sessionTimeout',  type: 'input',   label: 'Auto-logout idle sessions (seconds):',      default: '900' },
  ],

  generate({ options }) {
    const minLen   = parseInt(options.minPassLen      ?? '14');
    const lockout  = parseInt(options.lockoutAttempts ?? '5');
    const lockTime = parseInt(options.lockoutTime     ?? '900');
    const banner   = options.loginBanner   ?? true;
    const noCA     = options.ctrlAltDel    ?? true;
    const umask    = options.secureUmask   ?? true;
    const timeout  = parseInt(options.sessionTimeout  ?? '900');

    return `
# ── Login Security (openSUSE) ─────────────────────────────────────────
zypper install -y -n pam_pwquality

cat > /etc/security/pwquality.conf << 'PWQUAL'
minlen = ${minLen}
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
maxrepeat = 3
maxsequence = 4
gecoscheck = 1
PWQUAL

# Faillock config (openSUSE ≥15.3 ships pam_faillock)
cat > /etc/security/faillock.conf << 'FAIL'
deny = ${lockout}
unlock_time = ${lockTime}
fail_interval = 900
even_deny_root
root_unlock_time = 60
audit
FAIL

# Inject faillock into PAM common-auth if not already there
COMMON=/etc/pam.d/common-auth
if ! grep -q 'pam_faillock' "$COMMON"; then
  sed -i '0,/^auth/s//auth required pam_faillock.so preauth\nauth/' "$COMMON"
  echo 'auth [default=die] pam_faillock.so authfail' >> "$COMMON"
fi
ACCT=/etc/pam.d/common-account
grep -q 'pam_faillock' "$ACCT" || echo 'account required pam_faillock.so' >> "$ACCT"

${banner ? `
cat > /etc/issue << 'BANNER'
*******************************************
*   UNAUTHORIZED ACCESS IS PROHIBITED    *
*   All sessions are logged and audited  *
*******************************************
BANNER
cat /etc/issue > /etc/issue.net
` : ''}

${noCA ? `systemctl mask ctrl-alt-del.target` : ''}

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

sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/'  /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/'   /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/'  /etc/login.defs
grep -q '^ENCRYPT_METHOD' /etc/login.defs && \
  sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs || \
  echo 'ENCRYPT_METHOD SHA512' >> /etc/login.defs

echo '* hard core 0' >> /etc/security/limits.conf
`;
  },

  manifests() {
    return {
      created: [
        '/etc/security/pwquality.conf',
        '/etc/security/faillock.conf',
        '/etc/profile.d/sf-umask.sh',
        '/etc/profile.d/sf-timeout.sh',
      ],
      packages_installed: ['pam_pwquality'],
    };
  },
};
