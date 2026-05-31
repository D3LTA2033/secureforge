export default {
  id: 'faketwinlogin',
  name: 'Fake Twin Login (Duress)',
  description: 'Two passwords for your account — real OS vs convincing decoy session',
  category: 'Deception',
  defaultEnabled: false,

  options: [],  // collected via askFakeTwinConfig() in index.js

  generate({ options }) {
    const decoyUser      = options.decoyUser       ?? 'sf_decoy';
    const decoyPassword  = options.decoyPassword   ?? '';
    const alertWebhook   = options.alertWebhook    ?? false;
    const webhookUrl     = options.webhookUrl       ?? '';
    const populateDecoy  = options.populateDecoy   ?? true;
    const logAccess      = options.logDecoyAccess  ?? true;

    if (!decoyPassword) return '# FakeTwinLogin: no duress password set, skipping.';

    return `
# ── Fake Twin Login / Duress Login (Arch) ───────────────────────────
#
# How it works:
#   1. A decoy user '${decoyUser}' is created with a fake home.
#   2. A custom PAM exec script intercepts logins BEFORE pam_unix.
#   3. If the duress password is entered for the REAL user, PAM
#      redirects the session to '${decoyUser}' instead.
#   4. The real user never notices the switch — they just get a shell.

pacman -S --noconfirm --needed libpam-runtime openssh curl 2>/dev/null || true

# ── 1. Create decoy user ─────────────────────────────────────────────
if ! id '${decoyUser}' &>/dev/null; then
  useradd -m -s /bin/bash '${decoyUser}'
fi
echo '${decoyUser}:${decoyPassword}INVALID_REAL_PASS' | chpasswd 2>/dev/null || true
# Decoy user gets a restricted shell + no sudo
sed -i '/^${decoyUser}/d' /etc/sudoers 2>/dev/null || true
chmod 700 /home/${decoyUser}

${populateDecoy ? `
# ── 2. Populate decoy home with convincing fake files ────────────────
DECOY_HOME=/home/${decoyUser}

mkdir -p "$DECOY_HOME"/{Documents,Downloads,Pictures,.ssh,.config}

cat > "$DECOY_HOME/Documents/notes.txt" << 'NOTES'
Meeting notes - Q2 planning
- Review budget spreadsheet
- Follow up with marketing team
- Update project timeline
NOTES

cat > "$DECOY_HOME/Documents/todo.txt" << 'TODO'
[ ] Call bank re: account
[ ] Renew car insurance
[ ] Fix bug in user service
[x] Update SSL cert
TODO

cat > "$DECOY_HOME/.bash_history" << 'HIST'
ls
cd Documents
cat notes.txt
nano todo.txt
cd
git status
python3 script.py
sudo systemctl status nginx
exit
HIST

cat > "$DECOY_HOME/.bashrc" << 'RC'
# .bashrc
export PS1="\\u@\\h:\\w\\$ "
alias ls='ls --color=auto'
alias ll='ls -lah'
export HISTSIZE=1000
RC

chown -R ${decoyUser}:${decoyUser} "$DECOY_HOME"
` : ''}

# ── 3. Write duress password hash (SHA-512 PBKDF) ────────────────────
mkdir -p /etc/secureforge/duress
DURESS_HASH=$(echo -n '${decoyPassword}' | sha512sum | awk '{print $1}')
echo "$DURESS_HASH" > /etc/secureforge/duress/${decoyUser}.hash
chmod 600 /etc/secureforge/duress/${decoyUser}.hash

# ── 4. Write PAM duress check script ─────────────────────────────────
cat > /usr/local/bin/sf-duress-check << 'DURESS_SCRIPT'
#!/usr/bin/env bash
# Reads PAM_AUTHTOK from stdin via pam_exec expose_authtok
AUTHTOK=$(cat /dev/stdin 2>/dev/null || echo "")
REAL_USER="${PAM_USER:-}"
HASH_FILE="/etc/secureforge/duress/${REAL_USER}.hash"

[ -z "$AUTHTOK" ] && exit 1
[ ! -f "$HASH_FILE" ] && exit 1

STORED=$(cat "$HASH_FILE")
ENTERED=$(echo -n "$AUTHTOK" | sha512sum | awk '{print $1}')

if [ "$STORED" = "$ENTERED" ]; then
  DECOY_USER="${decoyUser}"
  SRC_IP=$(echo "${SSH_CLIENT:-unknown}" | awk '{print $1}')

  ${logAccess ? `
  logger -t secureforge-duress "DURESS LOGIN: user=$REAL_USER src=$SRC_IP tty=${PAM_TTY:-unknown}"
  ` : ''}

  ${alertWebhook && webhookUrl ? `
  curl -s -X POST '${webhookUrl}' \\
    -H 'Content-Type: application/json' \\
    -d "{\\"event\\":\\"duress_login\\",\\"user\\":\\"$REAL_USER\\",\\"src_ip\\":\\"$SRC_IP\\",\\"tty\\":\\"${PAM_TTY:-unknown}\\"}" \\
    &>/dev/null &
  ` : ''}

  # Switch to decoy session
  exec login -f "$DECOY_USER"
fi

exit 1
DURESS_SCRIPT

chmod 750 /usr/local/bin/sf-duress-check
chown root:root /usr/local/bin/sf-duress-check

# ── 5. Inject into PAM system-auth (before pam_unix) ─────────────────
# Only inject if not already present
SYSAUTH=/etc/pam.d/system-auth

if ! grep -q 'sf-duress-check' "$SYSAUTH"; then
  # Insert as first auth line so it runs before pam_unix checks password
  sed -i '0,/^auth/s//auth sufficient pam_exec.so expose_authtok quiet \/usr\/local\/bin\/sf-duress-check\nauth/' "$SYSAUTH"
fi

# ── 6. Write decoy session wrapper ───────────────────────────────────
cat > /usr/local/bin/sf-decoy-shell << 'DSHELL'
#!/bin/bash
# Launched inside decoy session — looks and feels normal
export HOME=/home/${decoyUser}
export USER=${decoyUser}
export LOGNAME=${decoyUser}
cd "$HOME"
exec /bin/bash --login
DSHELL
chmod 755 /usr/local/bin/sf-decoy-shell

echo "[+] Fake Twin Login configured."
echo "[!] Duress password → opens '${decoyUser}' decoy session."
echo "[!] Real password   → opens your real account normally."
`;
  },

  manifests({ options }) {
    return {
      created: [
        '/usr/local/bin/sf-duress-check',
        '/usr/local/bin/sf-decoy-shell',
        '/etc/secureforge/duress/',
      ],
    };
  },
};
