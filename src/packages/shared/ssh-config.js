export function sshConfig(opts = {}) {
  const port         = opts.port         ?? 22;
  const allowUsers   = opts.allowUsers   ?? [];
  const totp         = opts.totp         ?? false;
  const portKnocking = opts.portKnocking ?? false;

  const allowUsersLine = allowUsers.length
    ? `AllowUsers ${allowUsers.join(' ')}`
    : '# AllowUsers (add usernames to restrict SSH access)';

  return `
# SecureForge SSH Hardening — /etc/ssh/sshd_config.d/99-secureforge.conf
Port ${port}
Protocol 2

# Authentication
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey${totp ? ',keyboard-interactive' : ''}
PermitEmptyPasswords no
ChallengeResponseAuthentication ${totp ? 'yes' : 'no'}

# Session limits
MaxAuthTries 3
MaxSessions 5
LoginGraceTime 20
ClientAliveInterval 300
ClientAliveCountMax 2

# Access control
${allowUsersLine}

# Forwarding disabled
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
GatewayPorts no
PermitTunnel no

# Misc
PrintLastLog yes
Banner /etc/issue.net
LogLevel VERBOSE
StrictModes yes
IgnoreRhosts yes
HostbasedAuthentication no
UseDNS no
PermitUserEnvironment no
AcceptEnv LANG LC_*

# Strong ciphers / MACs / KEX only
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
`.trim();
}

export const SSH_BANNER = `
******************************************
*   UNAUTHORIZED ACCESS IS PROHIBITED   *
*   All activity is logged and audited   *
******************************************
`.trim();

export const TOTP_PAM_LINE = 'auth required pam_google_authenticator.so nullok';
