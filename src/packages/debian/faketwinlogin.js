export default {
  id: 'faketwinlogin',
  name: 'Fake Twin Login (Duress)',
  description: 'Two passwords — real OS vs convincing decoy session. Uses libpam-duress.',
  category: 'Deception',
  defaultEnabled: false,

  options: [],

  generate({ options }) {
    const decoyUser     = options.decoyUser      ?? 'sf_decoy';
    const decoyPassword = options.decoyPassword  ?? '';
    const alertWebhook  = options.alertWebhook   ?? false;
    const webhookUrl    = options.webhookUrl      ?? '';
    const populateDecoy = options.populateDecoy  ?? true;
    const logAccess     = options.logDecoyAccess ?? true;

    if (!decoyPassword) return '# FakeTwinLogin: no duress password set, skipping.';

    return `
# ── Fake Twin Login / Duress Login (Debian) ──────────────────────────
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq libpam-duress curl 2>/dev/null || true

# ── 1. Create decoy user ──────────────────────────────────────────────
if ! id '${decoyUser}' &>/dev/null; then
  useradd -m -s /bin/bash '${decoyUser}'
fi

${populateDecoy ? `
DECOY_HOME=/home/${decoyUser}
mkdir -p "$DECOY_HOME"/{Documents,Downloads,Pictures,.ssh,.config}

cat > "$DECOY_HOME/Documents/notes.txt" << 'NOTES'
Meeting notes - Q2 planning
- Review budget spreadsheet
- Follow up with marketing team
NOTES

cat > "$DECOY_HOME/.bash_history" << 'HIST'
ls
cd Documents
cat notes.txt
sudo apt update
git status
exit
HIST

cat > "$DECOY_HOME/.bashrc" << 'RC'
export PS1="\\u@\\h:\\w\\$ "
alias ls='ls --color=auto'
alias ll='ls -lah'
RC
chown -R ${decoyUser}:${decoyUser} "$DECOY_HOME"
` : ''}

# ── 2. libpam-duress setup ────────────────────────────────────────────
# libpam-duress runs scripts in ~/.duress/ when the duress password is entered.
# Each script filename is the SHA1 hash of the duress password.

REAL_USER=$(logname 2>/dev/null || who am i | awk '{print $1}')
REAL_HOME=$(eval echo "~$REAL_USER")
DURESS_DIR="$REAL_HOME/.duress"
mkdir -p "$DURESS_DIR"
chmod 700 "$DURESS_DIR"

DURESS_HASH=$(echo -n '${decoyPassword}' | sha1sum | awk '{print $1}')

cat > "$DURESS_DIR/$DURESS_HASH" << 'DSCRIPT'
#!/bin/bash
DECOY="${decoyUser}"
SRC_IP=$(echo "\${SSH_CLIENT:-}" | awk '{print $1}')

${logAccess ? `logger -t secureforge-duress "DURESS LOGIN triggered from $SRC_IP"` : ''}

${alertWebhook && webhookUrl ? `
curl -s -X POST '${webhookUrl}' \\
  -H 'Content-Type: application/json' \\
  -d "{\\"event\\":\\"duress_login\\",\\"src_ip\\":\\"$SRC_IP\\"}" &>/dev/null &
` : ''}

exec su - "$DECOY"
DSCRIPT

chmod 700 "$DURESS_DIR/$DURESS_HASH"
chown -R "$REAL_USER:$REAL_USER" "$DURESS_DIR"

# ── 3. Also set up PAM exec fallback ─────────────────────────────────
mkdir -p /etc/secureforge/duress
DURESS_HASH512=$(echo -n '${decoyPassword}' | sha512sum | awk '{print $1}')
echo "$DURESS_HASH512" > /etc/secureforge/duress/hash
chmod 600 /etc/secureforge/duress/hash

cat > /usr/local/bin/sf-duress-check << 'DURESS_SCRIPT'
#!/usr/bin/env bash
AUTHTOK=$(cat /dev/stdin 2>/dev/null || echo "")
HASH_FILE="/etc/secureforge/duress/hash"

[ -z "$AUTHTOK" ] && exit 1
[ ! -f "$HASH_FILE" ] && exit 1

STORED=$(cat "$HASH_FILE")
ENTERED=$(echo -n "$AUTHTOK" | sha512sum | awk '{print $1}')

if [ "$STORED" = "$ENTERED" ]; then
  SRC_IP=$(echo "\${SSH_CLIENT:-local}" | awk '{print $1}')
  ${logAccess ? `logger -t secureforge-duress "DURESS LOGIN: user=$PAM_USER src=$SRC_IP"` : ''}
  ${alertWebhook && webhookUrl ? `
  curl -s -X POST '${webhookUrl}' -H 'Content-Type: application/json' \
    -d "{\"event\":\"duress_login\",\"src_ip\":\"$SRC_IP\"}" &>/dev/null &
  ` : ''}
  exec login -f '${decoyUser}'
fi
exit 1
DURESS_SCRIPT
chmod 750 /usr/local/bin/sf-duress-check

# Inject into PAM common-auth
COMMON=/etc/pam.d/common-auth
grep -q 'sf-duress-check' "$COMMON" || \
  sed -i '0,/^auth/s//auth sufficient pam_exec.so expose_authtok quiet \/usr\/local\/bin\/sf-duress-check\nauth/' "$COMMON"

echo "[+] Fake Twin Login configured."
echo "[!] Entering duress password → '${decoyUser}' decoy session."
`;
  },

  manifests() {
    return {
      created: ['/usr/local/bin/sf-duress-check', '/etc/secureforge/duress/'],
      packages_installed: ['libpam-duress'],
    };
  },
};
