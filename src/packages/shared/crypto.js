import { pm } from './pkg.js';

export default {
  id: 'crypto',
  name: 'Crypto & TLS Hardening',
  description: 'Minimum TLS 1.2, disable weak ciphers/MACs, system-wide crypto policy',
  category: 'Cryptography',
  defaultEnabled: true,

  options: [
    { id: 'minTLS',        type: 'list',    label: 'Minimum TLS version:',           default: 'TLSv1.2',
      choices: [
        { name: 'TLS 1.2 (recommended)',    value: 'TLSv1.2' },
        { name: 'TLS 1.3 (strict)',         value: 'TLSv1.3' },
      ]
    },
    { id: 'disableSSL',    type: 'confirm', label: 'Disable SSLv2 / SSLv3 system-wide?',              default: true },
    { id: 'disableRC4',    type: 'confirm', label: 'Disable RC4, DES, 3DES, EXPORT ciphers?',         default: true },
    { id: 'disableMD5',    type: 'confirm', label: 'Disable MD5, SHA-1 for signatures?',              default: true },
    { id: 'cryptoPolicy',  type: 'list',    label: 'Policy level (RHEL/Fedora/CentOS only):',  default: 'DEFAULT',
      choices: [
        { name: 'DEFAULT — balanced security',          value: 'DEFAULT' },
        { name: 'DEFAULT:NO-SHA1 — disable SHA-1',      value: 'DEFAULT:NO-SHA1' },
        { name: 'FUTURE — strict forward-compat only',  value: 'FUTURE' },
        { name: 'FIPS — FIPS 140-2 compliance',         value: 'FIPS' },
      ]
    },
    { id: 'opensslHarden', type: 'confirm', label: 'Harden OpenSSL config (/etc/ssl/openssl.cnf)?',   default: true },
    { id: 'disableWeak',   type: 'confirm', label: 'Blacklist weak kernel crypto modules (md4, des)?', default: true },
  ],

  generate({ distro, options }) {
    const minTLS       = options.minTLS        ?? 'TLSv1.2';
    const disableSSL   = options.disableSSL    ?? true;
    const disableRC4   = options.disableRC4    ?? true;
    const disableMD5   = options.disableMD5    ?? true;
    const cryptoPolicy = options.cryptoPolicy  ?? 'DEFAULT:NO-SHA1';
    const opensslH     = options.opensslHarden ?? true;
    const disableWeak  = options.disableWeak   ?? true;

    const useCryptoPolicies = ['rhel', 'centos', 'fedora'].includes(distro);

    return `
# ── Crypto & TLS Hardening (${distro}) ────────────────────────────────

${useCryptoPolicies ? `
# RHEL/Fedora/CentOS: update-crypto-policies
update-crypto-policies --set ${cryptoPolicy} 2>/dev/null && \
  echo "[+] Crypto policy set to: ${cryptoPolicy}" || \
  echo "[!] update-crypto-policies not found — applying manual config"
` : ''}

${opensslH ? `
# OpenSSL system-wide hardening
OPENSSL_CONF=/etc/ssl/openssl.cnf
[ -f /etc/pki/tls/openssl.cnf ] && OPENSSL_CONF=/etc/pki/tls/openssl.cnf

cp "$OPENSSL_CONF" "$OPENSSL_CONF.sf.bak" 2>/dev/null || true

# Ensure [system_default_sect] exists
if ! grep -q 'system_default_sect' "$OPENSSL_CONF"; then
  echo '' >> "$OPENSSL_CONF"
  echo '[system_default_sect]' >> "$OPENSSL_CONF"
fi

# Apply settings to system_default_sect
python3 -c "
import configparser, sys
conf = configparser.ConfigParser(strict=False)
conf.read('$OPENSSL_CONF')
sect = 'system_default_sect'
if not conf.has_section(sect):
    conf.add_section(sect)
conf.set(sect, 'MinProtocol', '${minTLS}')
conf.set(sect, 'CipherString', 'DEFAULT:!aNULL:!eNULL:!RC4:!DES:!3DES:!MD5:!EXPORT${disableSSL ? ':!SSLv2:!SSLv3' : ''}')
conf.set(sect, 'Options', 'ServerPreference')
with open('$OPENSSL_CONF', 'w') as f:
    conf.write(f)
" 2>/dev/null || \
# Fallback: sed-based approach
cat >> "$OPENSSL_CONF" << 'SSLEOF'

[secureforge_crypto]
MinProtocol = ${minTLS}
CipherString = DEFAULT:!aNULL:!eNULL:!RC4:!DES:!3DES:${disableMD5 ? '!MD5:!SHA1:' : ''}!EXPORT${disableSSL ? ':!SSLv2:!SSLv3' : ''}
Options = ServerPreference
SSLEOF
` : ''}

${disableWeak ? `
# Blacklist weak/broken kernel crypto modules
cat > /etc/modprobe.d/sf-crypto.conf << 'MODS'
install md4      /bin/false
install des      /bin/false
install blowfish /bin/false
install cast5    /bin/false
install cast6    /bin/false
install twofish  /bin/false
install twofish_common /bin/false
MODS
` : ''}

${disableRC4 ? `
# Disable RC4 in OpenSSH (belt-and-suspenders — sshd config also does this)
if [ -f /etc/ssh/sshd_config ]; then
  grep -q '!ARCFOUR\|!RC4' /etc/ssh/sshd_config || \
    echo 'Ciphers -arcfour,arcfour128,arcfour256' >> /etc/ssh/sshd_config.d/99-secureforge.conf 2>/dev/null || true
fi
` : ''}

# Verify OpenSSL minimum version in effect
openssl ciphers -v 2>/dev/null | grep -E 'RC4|DES|EXPORT' | while read -r line; do
  echo "[!] Weak cipher still listed: $line" >&2
done || true

echo "[+] Crypto hardening applied. Min TLS: ${minTLS}"
`;
  },

  manifests({ options }) {
    return {
      created: [
        ...(options.disableWeak ? ['/etc/modprobe.d/sf-crypto.conf'] : []),
      ],
    };
  },
};
