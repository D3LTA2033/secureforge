export default {
  id: 'login',
  name: 'Login Security',
  description: 'PAM policy, password quality, account lockout, login banner, TTY hardening',
  category: 'Access Control',
  defaultEnabled: true,

  options: [
    { id: 'minPassLen',      type: 'input',   label: 'Minimum password length:',                default: '14',
      validate: v => (parseInt(v) >= 8 && parseInt(v) <= 64) || '8–64' },
    { id: 'lockoutAttempts', type: 'input',   label: 'Account lockout after N failed attempts:', default: '5',
      validate: v => parseInt(v) > 0 || 'Must be > 0' },
    { id: 'lockoutTime',     type: 'input',   label: 'Lockout duration (seconds):',             default: '900',
      validate: v => parseInt(v) >= 60 || 'Min 60s' },
    { id: 'secureTTY',       type: 'confirm', label: 'Restrict root login to specific TTYs?',   default: true },
    { id: 'loginBanner',     type: 'confirm', label: 'Set unauthorized-access login banner?',   default: true },
    { id: 'ctrlAltDel',      type: 'confirm', label: 'Disable Ctrl+Alt+Del reboot?',            default: true },
    { id: 'secureUmask',     type: 'confirm', label: 'Set secure umask (027)?',                 default: true },
    { id: 'sessionTimeout',  type: 'input',   label: 'Auto-logout idle sessions after (seconds, 0=off):', default: '900' },
  ],

  generate({ options }) {
    const minLen    = parseInt(options.minPassLen      ?? '14');
    const lockout   = parseInt(options.lockoutAttempts ?? '5');
    const lockTime  = parseInt(options.lockoutTime     ?? '900');
    const tty       = options.secureTTY       ?? true;
    const banner    = options.loginBanner     ?? true;
    const noCtrlAlt = options.ctrlAltDel      ?? true;
    const umask     = options.secureUmask     ?? true;
    const timeout   = parseInt(options.sessionTimeout  ?? '900');

    return `
# ── Login Security (Arch) ─────────────────────────────────────────────
pacman -S --noconfirm --needed libpwquality pam

# Password quality policy
cat > /etc/security/pwquality.conf << 'PWQUAL'
minlen = ${minLen}
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
maxrepeat = 3
maxsequence = 4
gecoscheck = 1
badwords = password pass 12345 qwerty
PWQUAL

# PAM account lockout — faillock
cat > /etc/security/faillock.conf << 'FAIL'
deny = ${lockout}
unlock_time = ${lockTime}
fail_interval = 900
even_deny_root
root_unlock_time = 60
audit
silent
FAIL

# Ensure faillock is in PAM auth chain (system-auth)
SYSAUTH=/etc/pam.d/system-auth
if ! grep -q 'pam_faillock' "$SYSAUTH"; then
  sed -i '/^auth.*pam_unix/i auth required pam_faillock.so preauth' "$SYSAUTH"
  sed -i '/^auth.*pam_unix/a auth [default=die] pam_faillock.so authfail' "$SYSAUTH"
  echo 'account required pam_faillock.so' >> "$SYSAUTH"
fi

${banner ? `
# Login banners
cat > /etc/issue << 'BANNER'
*******************************************
*   UNAUTHORIZED ACCESS IS PROHIBITED    *
*   All sessions are logged and audited  *
*******************************************

BANNER
cat /etc/issue > /etc/issue.net
` : ''}

${tty ? `
# Restrict root console to tty1 only
echo 'tty1' > /etc/securetty
` : ''}

${noCtrlAlt ? `
# Disable Ctrl+Alt+Del
systemctl mask ctrl-alt-del.target
` : ''}

${umask ? `
# Secure umask for all users
cat > /etc/profile.d/sf-umask.sh << 'UMASK'
umask 027
UMASK
chmod 644 /etc/profile.d/sf-umask.sh
` : ''}

${timeout > 0 ? `
# Auto-logout idle shells
cat > /etc/profile.d/sf-timeout.sh << 'TIMEOUT'
TMOUT=${timeout}
readonly TMOUT
export TMOUT
TIMEOUT
chmod 644 /etc/profile.d/sf-timeout.sh
` : ''}

# Harden /etc/login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/'  /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/'   /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/'  /etc/login.defs
sed -i 's/^LOGIN_RETRIES.*/LOGIN_RETRIES   ${lockout}/' /etc/login.defs
sed -i 's/^LOGIN_TIMEOUT.*/LOGIN_TIMEOUT   20/'  /etc/login.defs

# SHA512 password hashing
sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs
grep -q '^ENCRYPT_METHOD' /etc/login.defs || echo 'ENCRYPT_METHOD SHA512' >> /etc/login.defs

# Prevent core dumps for setuid programs
echo '* hard core 0' >> /etc/security/limits.conf
`;
  },

  manifests() {
    return {
      created: [
        '/etc/profile.d/sf-umask.sh',
        '/etc/profile.d/sf-timeout.sh',
        '/etc/security/pwquality.conf',
        '/etc/security/faillock.conf',
      ],
      packages_installed: ['libpwquality'],
    };
  },
};
