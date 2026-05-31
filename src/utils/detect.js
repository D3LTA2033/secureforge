import { readFileSync } from 'fs';
import { execSync } from 'child_process';

export function detectDistro() {
  try {
    const content = readFileSync('/etc/os-release', 'utf8').toLowerCase();
    if (content.includes('arch'))            return 'arch';
    if (content.includes('ubuntu'))          return 'ubuntu';
    if (content.includes('fedora'))          return 'fedora';
    if (content.includes('centos'))          return 'centos';
    if (content.includes('red hat') || content.includes('rhel')) return 'rhel';
    if (content.includes('opensuse'))        return 'opensuse';
    if (content.includes('debian'))          return 'debian';
    if (content.includes('gentoo'))          return 'gentoo';
    if (content.includes('alpine'))          return 'alpine';
  } catch {}
  return null;
}

export function detectArch() {
  try {
    return execSync('uname -m', { encoding: 'utf8' }).trim();
  } catch {
    return 'x86_64';
  }
}

export function isRoot() {
  return process.getuid && process.getuid() === 0;
}

export function hasSudo() {
  try {
    execSync('sudo -n true', { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

export function getHostname() {
  try {
    return execSync('hostname', { encoding: 'utf8' }).trim();
  } catch {
    return 'unknown';
  }
}

export function getInstalledVersion(bin) {
  try {
    const out = execSync(`${bin} --version 2>&1`, { encoding: 'utf8' });
    const match = out.match(/[\d]+\.[\d]+\.?[\d]*/);
    return match ? match[0] : null;
  } catch {
    return null;
  }
}
