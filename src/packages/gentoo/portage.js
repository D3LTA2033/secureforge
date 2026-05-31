export default {
  id: 'portage',
  name: 'Portage Hardening',
  description: '[ALPHA] Gentoo-specific: secure make.conf, FEATURES, EMERGE_DEFAULT_OPTS, GPG verify',
  category: 'Package Manager',
  maturity: 'alpha',
  defaultEnabled: true,

  options: [
    { id: 'gpgVerify',      type: 'confirm', label: 'Enforce GPG verification of Portage tree?',         default: true },
    { id: 'featuresSandbox',type: 'confirm', label: 'Enable Portage sandbox + usersandbox features?',    default: true },
    { id: 'featuresStrict', type: 'confirm', label: 'Enable strict + protect-owned features?',           default: true },
    { id: 'noSandboxBypass',type: 'confirm', label: 'Prevent network access in ebuilds (FEATURES=network-sandbox)?', default: true },
    { id: 'logEmerge',      type: 'confirm', label: 'Enable emerge logging to /var/log/portage/emerge.log?', default: true },
    { id: 'binhostDisable', type: 'confirm', label: 'Disable binary host packages (compile-only)?',      default: false },
    { id: 'syncVerify',     type: 'confirm', label: 'Verify repo sync integrity (gemato)?',              default: true },
  ],

  generate({ options }) {
    const gpg         = options.gpgVerify       ?? true;
    const sandbox     = options.featuresSandbox ?? true;
    const strict      = options.featuresStrict  ?? true;
    const netSandbox  = options.noSandboxBypass ?? true;
    const logging     = options.logEmerge       ?? true;
    const noBinhost   = options.binhostDisable  ?? false;
    const syncVerify  = options.syncVerify       ?? true;

    const features = [
      sandbox     ? 'sandbox usersandbox' : '',
      strict      ? 'strict protect-owned' : '',
      netSandbox  ? 'network-sandbox' : '',
      logging     ? 'binpkg-logs' : '',
      'collision-protect',
    ].filter(Boolean).join(' ');

    return `
# ── Portage Hardening (Gentoo) ────────────────────────────────────────
# [ALPHA] Hardens the Portage package manager itself.
MAKECONF=/etc/portage/make.conf

# Backup make.conf
cp "$MAKECONF" "$MAKECONF.sf.bak.$(date +%s)"

# Add FEATURES if not present
grep -q '^FEATURES=' "$MAKECONF" && \
  sed -i "s|^FEATURES=.*|FEATURES=\"${features}\"|" "$MAKECONF" || \
  echo 'FEATURES="${features}"' >> "$MAKECONF"

${logging ? `
# Enable emerge logging
grep -q '^PORT_LOGDIR' "$MAKECONF" || \
  echo 'PORT_LOGDIR="/var/log/portage"' >> "$MAKECONF"
mkdir -p /var/log/portage
chmod 750 /var/log/portage
` : ''}

${noBinhost ? `
# Disable binary packages (force compile from source)
grep -q '^PORTAGE_BINHOST' "$MAKECONF" && \
  sed -i '/^PORTAGE_BINHOST/d' "$MAKECONF" || true
` : ''}

${gpg ? `
# GPG verification of Portage tree
mkdir -p /etc/portage
cat > /etc/portage/repos.conf/gentoo.conf << 'REPOCONF'
[gentoo]
location = /var/db/repos/gentoo
sync-type = rsync
sync-uri = rsync://rsync.gentoo.org/gentoo-portage
auto-sync = yes
${syncVerify ? 'sync-rsync-verify-jobs = 1\nsync-rsync-verify-metamanifest = yes\nsync-rsync-verify-max-age = 24' : ''}
REPOCONF
` : ''}

${syncVerify ? `
# Install gemato for manifest verification
emerge --ask=n app-portage/gemato 2>/dev/null || true
` : ''}

# Safe emerge defaults
grep -q 'EMERGE_DEFAULT_OPTS' "$MAKECONF" || \
  echo 'EMERGE_DEFAULT_OPTS="--ask=n --quiet-build=n --fail-clean=y"' >> "$MAKECONF"

echo "[+] Portage hardening applied."
echo "[!] To apply new FEATURES: emerge --ask -uDN @world"
echo "[!] Full compile of world may take hours — schedule accordingly."
`;
  },

  manifests() {
    return {
      backups: [{ original: '/etc/portage/make.conf', backup: '/etc/portage/make.conf.sf.bak' }],
      created: ['/var/log/portage/'],
    };
  },
};
