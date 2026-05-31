export default {
  id: 'faketwinlogin',
  name: 'Fake Twin Login (Duress)',
  description: 'Two passwords — real OS vs decoy session via PAM exec',
  category: 'Deception',
  defaultEnabled: false,
  options: [],

  generate({ options }) {
    const decoyUser     = options.decoyUser      ?? 'sf_decoy';
    const decoyPassword = options.decoyPassword  ?? '';
    const populateDecoy = options.populateDecoy  ?? true;
    const logAccess     = options.logDecoyAccess ?? true;

    if (!decoyPassword) return '# FakeTwinLogin: no duress password set, skipping.';

    return `
# ── Fake Twin Login (Alpine) ──────────────────────────────────────────
# [ALPHA] Alpine PAM duress hook.
apk add --no-cache shadow

if ! id '${decoyUser}' &>/dev/null; then
  adduser -D -s /bin/sh '${decoyUser}' 2>/dev/null || useradd -m -s /bin/sh '${decoyUser}'
fi
passwd -l '${decoyUser}' 2>/dev/null || true

${populateDecoy ? `
DECOY_HOME=/home/${decoyUser}
mkdir -p "$DECOY_HOME"/{Documents,.ssh}
cat > "$DECOY_HOME/Documents/notes.txt" << 'NOTES'
Work notes
- Update configs
- Review logs
NOTES
cat > "$DECOY_HOME/.ash_history" << 'HIST'
ls
cat Documents/notes.txt
apk update
exit
HIST
chown -R ${decoyUser}:${decoyUser} "$DECOY_HOME"
` : ''}

mkdir -p /etc/secureforge/duress
DURESS_HASH=$(echo -n '${decoyPassword}' | sha512sum | awk '{print $1}')
echo "$DURESS_HASH" > /etc/secureforge/duress/hash
chmod 600 /etc/secureforge/duress/hash

cat > /usr/local/bin/sf-duress-check << 'DURESS_SCRIPT'
#!/bin/sh
AUTHTOK=$(cat /dev/stdin 2>/dev/null || echo "")
HASH_FILE="/etc/secureforge/duress/hash"
[ -z "$AUTHTOK" ] && exit 1
[ ! -f "$HASH_FILE" ] && exit 1
STORED=$(cat "$HASH_FILE")
ENTERED=$(echo -n "$AUTHTOK" | sha512sum | awk '{print $1}')
if [ "$STORED" = "$ENTERED" ]; then
  SRC_IP=$(echo "\${SSH_CLIENT:-local}" | awk '{print $1}')
  ${logAccess ? `logger -t secureforge-duress "DURESS LOGIN: user=$PAM_USER src=$SRC_IP"` : ''}
  exec login -f '${decoyUser}'
fi
exit 1
DURESS_SCRIPT
chmod 750 /usr/local/bin/sf-duress-check

SYSAUTH=/etc/pam.d/sshd
grep -q 'sf-duress-check' "$SYSAUTH" 2>/dev/null || \
  echo 'auth sufficient pam_exec.so expose_authtok quiet /usr/local/bin/sf-duress-check' >> "$SYSAUTH" || true

echo "[+] Fake Twin Login configured for Alpine."
`;
  },

  manifests() {
    return { created: ['/usr/local/bin/sf-duress-check', '/etc/secureforge/duress/'] };
  },
};
