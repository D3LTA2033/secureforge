import axios from 'axios';

const GH_API = 'https://api.github.com/repos';

const TRACKED = [
  { id: 'fail2ban',     repo: 'fail2ban/fail2ban' },
  { id: 'lynis',        repo: 'CISOfy/lynis' },
  { id: 'rkhunter',     repo: 'rootkit-hunter/rkhunter' },
  { id: 'google-auth',  repo: 'google/google-authenticator-libpam' },
  { id: 'firehol',      repo: 'firehol/firehol' },
  { id: 'auditd',       repo: 'linux-audit/audit-userspace' },
  { id: 'apparmor',     repo: 'apparmorproject/apparmor' },
  { id: 'clamav',       repo: 'Cisco-Talos/clamav' },
  { id: 'snort',        repo: 'snort3/snort3' },
  { id: 'suricata',     repo: 'OISF/suricata' },
];

export async function fetchLatestVersions(spinner) {
  const versions = {};
  const headers = { 'User-Agent': 'SecureForge-Hardening-Tool' };

  await Promise.allSettled(
    TRACKED.map(async ({ id, repo }) => {
      try {
        const { data } = await axios.get(`${GH_API}/${repo}/releases/latest`, {
          headers,
          timeout: 5000,
        });
        versions[id] = data.tag_name?.replace(/^v/, '') ?? 'unknown';
      } catch {
        versions[id] = 'unknown';
      }
    })
  );

  return versions;
}

export async function getLatestRelease(repo) {
  try {
    const { data } = await axios.get(`${GH_API}/${repo}/releases/latest`, {
      headers: { 'User-Agent': 'SecureForge-Hardening-Tool' },
      timeout: 5000,
    });
    return {
      version: data.tag_name?.replace(/^v/, ''),
      url: data.html_url,
      tarball: data.tarball_url,
    };
  } catch {
    return null;
  }
}
