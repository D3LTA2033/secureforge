export default {
  id: 'login',
  name: 'Login Security',
  description: 'PAM faillock, password quality, banner, session timeout — musl-aware',
  category: 'Access Control',
  defaultEnabled: true,

  options: [
    { id: 'minPassLen',      type: 'input',   label: 'Minimum password length:',        default: '14' },
    { id: 'lockoutAttempts', type: 'input',   label: 'Lockout after N failed attempts:', default: '5' },
    { id: 'lockoutTime',     type: 'input',   label: 'Lockout duration (seconds):',      default: '900' },
    { id: 'loginBanner',     type: 'confirm', label: 'Set unauthorized-access banner?',  default: true },
    { id: 'secureUmask',     type: 'confirm', label: 'Set secure umask (027)?',           default: true },
    { id: 'sessionTimeout',  type: 'input',   label: 'Auto-logout idle sessions (sec):',  default: '900' },
    { id: 'disableRoot',     type: 'confirm', label: 'Disable root login via console?',   default: false },
  ],

  generate({ options }) {
    const minLen   = parseInt(options.minPassLen      ?? '14');
    const lockout  = parseInt(options.lockoutAttempts ?? '5');
    const lockTime = parseInt(options.lockoutTime     ?? '900');
    const banner   = options.loginBanner   ?? true;
    const umask    = options.secureUmask   ?? true;
    const timeout  = parseInt(options.sessionTimeout  ?? '900');
    const noRoot   = options.disableRoot   ?? false;

    return `
# ── Login Security (Alpine) ───────────────────────────────────────────
# [ALPHA] Alpine uses musl libc — some PAM modules behave differently.
apk add --no-cache linux-pam shadow

# Password quality via /etc/login.defs (Alpine doesn't ship libpwquality by default)
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/'  /etc/login.defs 2>/dev/null || true
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/'   /etc/login.defs 2>/dev/null || true
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/'  /etc/login.defs 2>/dev/null || true
grep -q '^PASS_MIN_LEN'  /etc/login.defs && \
  sed -i "s/^PASS_MIN_LEN.*/PASS_MIN_LEN   ${minLen}/" /etc/login.defs || \
  echo "PASS_MIN_LEN   ${minLen}" >> /etc/login.defs

# faillock config (if available)
if [ -f /etc/security/faillock.conf ] || pam-auth-update 2>/dev/null; then
  cat > /etc/security/faillock.conf << 'FAIL'
deny = ${lockout}
unlock_time = ${lockTime}
fail_interval = 900
even_deny_root
root_unlock_time = 60
FAIL
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

${noRoot ? `
# Remove root from securetty (disables console root login)
echo '' > /etc/securetty
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

echo '* hard core 0' >> /etc/security/limits.conf 2>/dev/null || true
`;
  },

  manifests() {
    return {
      created: ['/etc/profile.d/sf-umask.sh', '/etc/profile.d/sf-timeout.sh'],
    };
  },
};
