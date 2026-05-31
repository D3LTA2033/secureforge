// Distro-aware package install helpers
export const install = {
  arch:     (pkgs) => `pacman -S --noconfirm --needed ${pkgs}`,
  debian:   (pkgs) => `DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ${pkgs}`,
  ubuntu:   (pkgs) => `DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ${pkgs}`,
  fedora:   (pkgs) => `dnf install -y ${pkgs}`,
  rhel:     (pkgs) => `dnf install -y ${pkgs}`,
  centos:   (pkgs) => `dnf install -y ${pkgs}`,
  opensuse: (pkgs) => `zypper install -y -n ${pkgs}`,
  gentoo:   (pkgs) => `emerge --ask=n ${pkgs}`,
  alpine:   (pkgs) => `apk add --no-cache ${pkgs}`,
};

// OpenRC-based distros (no systemd)
export const OPENRC_DISTROS = new Set(['gentoo', 'alpine']);

export function isOpenRC(distro) {
  return OPENRC_DISTROS.has(distro);
}

// Service enable/start helpers — returns shell snippet
export function svcEnable(distro, name) {
  return isOpenRC(distro)
    ? `rc-update add ${name} default 2>/dev/null || true`
    : `systemctl enable ${name}`;
}

export function svcStart(distro, name) {
  return isOpenRC(distro)
    ? `rc-service ${name} start 2>/dev/null || true`
    : `systemctl start ${name}`;
}

export function svcRestart(distro, name) {
  return isOpenRC(distro)
    ? `rc-service ${name} restart 2>/dev/null || true`
    : `systemctl restart ${name}`;
}

export function svcEnableNow(distro, name) {
  return isOpenRC(distro)
    ? `rc-update add ${name} default 2>/dev/null && rc-service ${name} start 2>/dev/null || true`
    : `systemctl enable --now ${name}`;
}

export function svcDisable(distro, name) {
  return isOpenRC(distro)
    ? `rc-update del ${name} default 2>/dev/null || true\nrc-service ${name} stop 2>/dev/null || true`
    : `systemctl disable --now ${name} 2>/dev/null || true`;
}

export function daemonReload(distro) {
  return isOpenRC(distro) ? '# (no daemon-reload needed for OpenRC)' : 'systemctl daemon-reload';
}

// Package name per distro (null = not available in default repos)
export const pkgName = {
  usbguard: { arch: 'usbguard', debian: 'usbguard', ubuntu: 'usbguard', fedora: 'usbguard', rhel: 'usbguard', centos: 'usbguard', opensuse: 'usbguard', gentoo: 'sys-apps/usbguard',    alpine: 'usbguard'   },
  chrony:   { arch: 'chrony',   debian: 'chrony',   ubuntu: 'chrony',   fedora: 'chrony',   rhel: 'chrony',   centos: 'chrony',   opensuse: 'chrony',   gentoo: 'net-misc/chrony',      alpine: 'chrony'     },
  suricata: { arch: 'suricata', debian: 'suricata', ubuntu: 'suricata', fedora: 'suricata', rhel: 'suricata', centos: 'suricata', opensuse: 'suricata', gentoo: 'net-analyzer/suricata', alpine: 'suricata'   },
  acct:     { arch: 'acct',     debian: 'acct',     ubuntu: 'acct',     fedora: 'psacct',   rhel: 'psacct',   centos: 'psacct',   opensuse: 'acct',     gentoo: 'sys-process/acct',     alpine: 'acct'       },
  aide:     { arch: 'aide',     debian: 'aide',     ubuntu: 'aide',     fedora: 'aide',     rhel: 'aide',     centos: 'aide',     opensuse: 'aide',     gentoo: 'app-forensics/aide',   alpine: 'aide'       },
  fail2ban: { arch: 'fail2ban', debian: 'fail2ban', ubuntu: 'fail2ban', fedora: 'fail2ban', rhel: 'fail2ban', centos: 'fail2ban', opensuse: 'fail2ban', gentoo: 'net-analyzer/fail2ban',alpine: 'fail2ban'   },
  lynis:    { arch: 'lynis',    debian: 'lynis',    ubuntu: 'lynis',    fedora: 'lynis',    rhel: 'lynis',    centos: 'lynis',    opensuse: 'lynis',    gentoo: 'app-admin/lynis',      alpine: 'lynis'      },
  rkhunter: { arch: 'rkhunter', debian: 'rkhunter', ubuntu: 'rkhunter', fedora: 'rkhunter', rhel: 'rkhunter', centos: 'rkhunter', opensuse: 'rkhunter', gentoo: 'app-admin/rkhunter',   alpine: 'rkhunter'   },
  inotify:  { arch: 'inotify-tools', debian: 'inotify-tools', ubuntu: 'inotify-tools', fedora: 'inotify-tools', rhel: 'inotify-tools', centos: 'inotify-tools', opensuse: 'inotify-tools', gentoo: 'sys-fs/inotify-tools', alpine: 'inotify-tools' },
};

export function pm(distro) {
  return install[distro] ?? install.debian;
}

export function pkg(distro, name) {
  return pkgName[name]?.[distro] ?? name;
}
