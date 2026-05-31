export default {
  id: 'geofence',
  name: 'GeoIP Login Fence',
  description: '[BETA] Block SSH logins from countries outside your allowlist via PAM + ip-api',
  category: 'Access Control',
  maturity: 'beta',
  defaultEnabled: false,

  options: [
    { id: 'allowedCountries', type: 'input',   label: 'Allowed country codes (comma-separated, e.g. US,GB,CA):', default: '',
      validate: v => v.trim().length > 0 || 'Specify at least one country code' },
    { id: 'allowLocal',       type: 'confirm', label: 'Always allow local / private IP logins?',    default: true },
    { id: 'logBlocked',       type: 'confirm', label: 'Log blocked login attempts to syslog?',      default: true },
    { id: 'alertWebhook',     type: 'confirm', label: 'Webhook alert on blocked attempt?',           default: false },
    { id: 'webhookUrl',       type: 'input',   label: 'Webhook URL:',                               default: '' },
    { id: 'cacheResults',     type: 'confirm', label: 'Cache GeoIP lookups (reduce API calls)?',    default: true },
    { id: 'offlineMode',      type: 'confirm', label: 'Offline fallback: block ALL if API unreachable?', default: false },
  ],

  generate({ options }) {
    const allowed    = (options.allowedCountries ?? '').trim().toUpperCase();
    const allowLocal = options.allowLocal    ?? true;
    const logBlocked = options.logBlocked    ?? true;
    const webhook    = options.alertWebhook  ?? false;
    const webhookUrl = options.webhookUrl    ?? '';
    const cache      = options.cacheResults  ?? true;
    const offline    = options.offlineMode   ?? false;

    if (!allowed) return '# GeoFence: no allowed countries configured, skipping.';

    return `
# ── GeoIP Login Fence (PAM) ───────────────────────────────────────────
# [BETA] Uses ip-api.com (free, no API key) for country lookups.
# Inject into PAM to block SSH from unauthorized countries.

# Install curl (needed for lookups)
command -v curl &>/dev/null || true

# ── Write geofence check script ───────────────────────────────────────
mkdir -p /etc/secureforge
cat > /usr/local/bin/sf-geofence << 'GEOCHECK'
#!/usr/bin/env bash
# SecureForge GeoIP Login Fence
# Called by PAM — $PAM_USER, $SSH_CONNECTION are set by sshd

ALLOWED="${allowed}"
SRC_IP=$(echo "$SSH_CONNECTION" | awk '{print $1}')
CACHE_DIR=/var/cache/sf-geofence
CACHE_TTL=86400  # 24 hours

${cache ? `
mkdir -p "$CACHE_DIR"
CACHE_FILE="$CACHE_DIR/$(echo "$SRC_IP" | tr '.' '-').geo"

# Use cached result if fresh
if [[ -f "$CACHE_FILE" ]]; then
  AGE=$(( $(date +%s) - $(stat -c %Y "$CACHE_FILE" 2>/dev/null || echo 0) ))
  if [[ $AGE -lt $CACHE_TTL ]]; then
    COUNTRY=$(cat "$CACHE_FILE")
  fi
fi
` : ''}

# Private / local IPs — always allow
${allowLocal ? `
case "$SRC_IP" in
  127.*|10.*|192.168.*|172.16.*|172.17.*|172.18.*|172.19.*|172.2*|172.3*|::1|"")
    exit 0  # Allow local/private IPs without geo check
    ;;
esac
` : ''}

# Blank src IP = local terminal login — allow
[[ -z "$SRC_IP" ]] && exit 0

# Lookup country from ip-api.com
if [[ -z "$COUNTRY" ]]; then
  COUNTRY=$(curl -s --max-time 3 "http://ip-api.com/line/${SRC_IP}?fields=countryCode" 2>/dev/null)
  EXIT_CODE=$?

  if [[ $EXIT_CODE -ne 0 || -z "$COUNTRY" ]]; then
    ${offline ? `
    logger -t sf-geofence "API unreachable for $SRC_IP — blocking (offline mode)"
    exit 1
    ` : `
    logger -t sf-geofence "API unreachable for $SRC_IP — allowing (online mode)"
    exit 0
    `}
  fi

  ${cache ? `echo "$COUNTRY" > "$CACHE_FILE"` : ''}
fi

# Check if allowed
if echo "$ALLOWED" | tr ',' '\n' | grep -qx "$COUNTRY"; then
  exit 0  # Allowed country
fi

# Blocked
MSG="GEOFENCE BLOCKED: user=$PAM_USER src=$SRC_IP country=$COUNTRY allowed=$ALLOWED"

${logBlocked ? `logger -t sf-geofence "$MSG"` : ''}
${webhook && webhookUrl ? `
curl -s -X POST '${webhookUrl}' -H 'Content-Type: application/json' \
  -d "{\"event\":\"geofence_block\",\"user\":\"$PAM_USER\",\"src_ip\":\"$SRC_IP\",\"country\":\"$COUNTRY\"}" \
  &>/dev/null &
` : ''}

echo "Access denied: connections from $COUNTRY are not permitted." >&2
exit 1
GEOCHECK

chmod 750 /usr/local/bin/sf-geofence
${cache ? 'mkdir -p /var/cache/sf-geofence && chmod 700 /var/cache/sf-geofence' : ''}

# ── Inject into PAM sshd ─────────────────────────────────────────────
SSHD_PAM=/etc/pam.d/sshd
if ! grep -q 'sf-geofence' "$SSHD_PAM"; then
  echo 'account required pam_exec.so /usr/local/bin/sf-geofence' >> "$SSHD_PAM"
fi

# ── Make sshd use PAM ──────────────────────────────────────────────────
SSH_DROPIN=/etc/ssh/sshd_config.d/99-secureforge.conf
if [ -f "$SSH_DROPIN" ]; then
  grep -q '^UsePAM' "$SSH_DROPIN" || echo 'UsePAM yes' >> "$SSH_DROPIN"
fi

# Reload SSH
systemctl restart sshd 2>/dev/null || rc-service sshd restart 2>/dev/null || true

echo "[+] GeoIP Login Fence active."
echo "[+] Allowed countries: ${allowed}"
echo "[!] Uses ip-api.com — requires outbound HTTP access from this server."
echo "[!] Country code reference: https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2"
`;
  },

  manifests() {
    return {
      created: ['/usr/local/bin/sf-geofence', '/var/cache/sf-geofence/'],
    };
  },
};
