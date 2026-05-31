<div align="center">

```
 ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗
 ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝
 ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗
 ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝
 ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗
 ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
  ███████╗ ██████╗ ██████╗  ██████╗ ███████╗
  ██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
  █████╗  ██║   ██║██████╔╝██║  ███╗█████╗
  ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
  ██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
  ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
```

**Interactive Linux OS Hardening Wizard**

[![Node.js](https://img.shields.io/badge/Node.js-18%2B-green?logo=node.js)](https://nodejs.org)
[![License](https://img.shields.io/badge/license-SPL--1.0-blue)](LICENSE)
[![Distros](https://img.shields.io/badge/distros-9-orange)](#supported-distros)
[![Modules](https://img.shields.io/badge/modules-21%2B-purple)](#module-reference)
[![Status](https://img.shields.io/badge/status-active%20development-yellow)](#)

*Asks how your system is set up. Lets you pick exactly what to lock down. Runs the scripts. Done.*

</div>

---

> **Warning**
> SecureForge makes **real, system-level changes** requiring root/sudo.
> Always test in a VM first. Use `--dry-run` to preview scripts before applying.
> Some distros and modules are marked **Alpha/Beta** — read the [maturity guide](#maturity-levels) before proceeding.

---

## What is SecureForge?

SecureForge is a modular, interactive CLI hardening wizard for Linux. Instead of a one-size-fits-all script, it:

- **Interviews** you about your machine's role, exposure, and distro
- **Shows every module** as a checkbox — enable or disable anything
- **Fetches the latest package versions** from GitHub before running
- **Writes hardening to the right system paths** (`/etc/`, `/usr/local/bin/`, etc.)
- **Tracks all changes** in a manifest so you can fully uninstall
- **Warns you** when a distro or module is Alpha/Beta/Experimental

Built in pure JavaScript (ESM, Node 18+). No Python, no Ansible, no cloud dependencies.

---

## Quick Start

```bash
# Clone and install
git clone https://github.com/D3LTA2033/secureforge
cd secureforge
npm install

# Preview what would happen (no changes made)
node index.js --dry-run

# Run the wizard
sudo node index.js

# Or after install.sh:
sudo bash install.sh
secureforge
```

---

## Supported Distros

| Distro | Package Manager | Init System | Firewall | MAC | Maturity |
|--------|----------------|-------------|----------|-----|----------|
| **Arch Linux** | pacman | systemd | UFW / nftables | — | ✅ Stable |
| **Debian** | apt | systemd | UFW / nftables / iptables | AppArmor | ✅ Stable |
| **Ubuntu** | apt | systemd | UFW / nftables | AppArmor | ✅ Stable |
| **Fedora** | dnf | systemd | firewalld | SELinux | ✅ Stable |
| **RHEL 8/9** | dnf | systemd | firewalld | SELinux | ⚠️ Beta |
| **CentOS / Stream** | dnf | systemd | firewalld | SELinux | ⚠️ Beta |
| **openSUSE** | zypper | systemd | firewalld | AppArmor | ⚠️ Beta |
| **Gentoo** | emerge (Portage) | OpenRC | nftables | PaX / grsec | ⚡ Alpha |
| **Alpine Linux** | apk | OpenRC | nftables / awall | — | ⚡ Alpha |

---

## Maturity Levels

| Badge | Meaning |
|-------|---------|
| ✅ **Stable** | Tested, reliable, safe to use in production (with care) |
| ⚠️ **Beta** | Works on most setups — edge cases may fail. Test first. |
| ⚡ **Alpha** | Early support. Scripts may fail on non-default configurations. VM only. |
| 🧪 **Experimental** | Custom/novel modules. Concepts are sound but may need tweaking per-system. |

SecureForge shows a **full-screen warning with a "Proceed? [N]"** prompt (defaulting to No) whenever you select an Alpha or Beta distro, and marks experimental modules inline in the checkbox list.

---

## Module Reference

All modules are individually **toggleable**. Each has configurable sub-options shown after selection.

### Core Hardening (all distros)

| Module | Category | Default | Description |
|--------|----------|---------|-------------|
| `ssh` | Access Control | ✅ on | Key-only auth, cipher lockdown, TOTP 2FA, port knocking, client hardening |
| `network` | Network | ✅ on | sysctl stack hardening, unused protocol blacklist, DNS-over-TLS, auto-updates |
| `kernel` | Kernel | ✅ on | ASLR, ptrace scope, BPF restrict, dmesg restrict, module blacklist, boot params |
| `firewall` | Network | ✅ on | UFW / nftables / firewalld — role-based port rules, rate limiting, logging |
| `login` | Access Control | ✅ on | PAM faillock, password quality, session timeout, banners, umask, Ctrl+Alt+Del |
| `root` | Access Control | ✅ on | Lock root, sudo hardening, su restriction, wheel-only escalation |
| `audit` | Monitoring | ✅ on | auditd ruleset, fail2ban SSH jail, rkhunter, lynis, remote syslog |
| `filesystem` | Filesystem | ✅ on | /tmp noexec, /dev/shm hardening, sticky bits, SUID audit, critical file perms |
| `services` | Services | ✅ on | Disable avahi/cups/bluetooth/NFS, systemd unit sandboxing, cron restriction |

### Deeper Security

| Module | Category | Default | Maturity | Description |
|--------|----------|---------|----------|-------------|
| `usbguard` | Hardware | ❌ off | ⚠️ Beta | Whitelist authorized USB devices — block everything else at kernel level |
| `ntp` | Network | ✅ on | ✅ Stable | Chrony with NTS (authenticated NTP), drift alerting, disable timesyncd |
| `grubpassword` | Boot Security | ❌ off | ✅ Stable | PBKDF2 GRUB superuser password — locks recovery/edit mode |
| `crypto` | Cryptography | ✅ on | ⚠️ Beta | Min TLS 1.2+, disable RC4/DES/MD5, system-wide crypto policy (RHEL/Fedora) |
| `ids` | Monitoring | ❌ off | ⚠️ Beta | Suricata IDS — auto-detect interface, ET Open rules, JSON event log |
| `acct` | Monitoring | ✅ on | ⚠️ Beta | Process accounting, hardened shell history, per-user command alerting |
| `memforge` | Kernel | ❌ off | ⚠️ Beta | seccomp BPF for sshd/nginx, ASLR verify, heap guard, PIE/RELRO audit |
| `procguard` | Monitoring | ❌ off | ⚠️ Beta | Process watchdog — auto-restart critical services + webhook alert on crash |
| `scap` | Compliance | ❌ off | ⚠️ Beta | OpenSCAP scan + remediation — CIS, DISA STIG, NIST 800-171, PCI-DSS (RHEL/CentOS) |

### Deception & Threat Intelligence

| Module | Category | Default | Maturity | Description |
|--------|----------|---------|----------|-------------|
| `faketwinlogin` | Deception | ❌ off | ✅ Stable | Two passwords — one opens your real OS, one silently opens a decoy session |
| `tarpit` | Deception | ❌ off | 🧪 Experimental | endlessh SSH tarpit on port 22 — holds attacker connections open indefinitely |
| `canary` | Deception | ❌ off | 🧪 Experimental | Plant fake credentials/keys — any read triggers instant alert + optional kill |
| `geofence` | Access Control | ❌ off | ⚠️ Beta | Block SSH logins from countries outside your allowlist via PAM + ip-api |

### Distro-Specific

| Module | Distro | Category | Description |
|--------|--------|----------|-------------|
| `portage` | Gentoo | Package Manager | Secure make.conf, FEATURES sandbox/strict/network-sandbox, GPG verification, hardened USE flags |

---

## CLI Flags

```
secureforge [options]

  (no flags)           Interactive wizard
  --dry-run            Show generated scripts without applying anything
  --list               List all available modules with maturity + default state
  --distro <name>      Skip detection: arch | debian | ubuntu | fedora | rhel | centos | opensuse | gentoo | alpine
  --yes                Skip final confirmation prompt
  -V, --version        Print version
```

---

## Notable Features

### Fake Twin Login (Duress Password)

Configure two passwords for your user account:

- **Password 1** (real) → logs into your actual OS session normally
- **Password 2** (duress) → silently redirects into a convincing decoy user session

The duress mechanism is implemented at the PAM layer via `pam_exec`. The decoy session gets a populated fake home directory with realistic-looking `.bash_history`, `Documents/notes.txt`, and more.

On Debian/Ubuntu: uses `libpam-duress` + custom PAM exec.
On Arch/Gentoo/Alpine/RHEL: custom `pam_exec` hook with SHA-512 hashed duress token.

Optional: webhook alert + syslog logging when the duress password is used.

```
Real password   → your actual shell
Duress password → decoy user 'sf_decoy', looks totally normal
```

---

### SSH Tarpit (endlessh)

Compiles [endlessh](https://github.com/skeeto/endlessh) from source and runs it on port 22. Endlessh sends an infinite SSH banner — attackers are trapped in a connection that never resolves, tying up their threads and slowing scans to a crawl.

Your real SSH daemon moves to a custom port (e.g. 2222). Optionally auto-bans repeat offenders with fail2ban.

```
Port 22   → endlessh tarpit (attacker stuck forever)
Port 2222 → real sshd (your actual access)
```

---

### Canary Files

Plants realistic-looking fake sensitive files in a hidden directory:

- `passwords.txt` — fake company credentials
- `id_rsa` — fake RSA private key (syntactically valid)
- `.aws-credentials` — fake AWS access keys
- `db_backup.sql` — fake database dump with user table

An `inotifywait` daemon watches them 24/7. Any `read`, `open`, or `access` event fires immediately — logging to syslog, hitting a webhook, and optionally killing the accessing process.

```
Attacker finds /opt/.canary/passwords.txt
→ inotifywait fires instantly
→ syslog + webhook alert: "CANARY TRIGGERED: user=www-data pid=12345 file=passwords.txt"
```

---

### GeoIP Login Fence

Adds a PAM `account` hook to SSH that checks the source IP's country via [ip-api.com](https://ip-api.com) (free, no API key). Rejects connections from countries not in your allowlist.

- Caches results 24h to avoid repeated API calls
- Always allows private/local IPs
- Configurable offline behavior (block all vs. allow all if API unreachable)

---

### MemForge

Layered memory attack surface reduction:

- **ASLR** enforcement (level 2, verified live)
- **seccomp BPF** syscall filters for sshd and nginx via systemd drop-ins
- **Heap guard** (`MALLOC_CHECK_=3`, `MALLOC_PERTURB_`) via `/etc/profile.d/`
- **LD_PRELOAD scrubbing** in sudo via sudoers `env_delete`
- **THP hardening** (madvise mode, defer+madvise defrag)
- **Binary security audit** — checks PIE, RELRO, NX, stack canary on sshd/sudo/bash

---

## What Gets Written to the System

| Path | Purpose |
|------|---------|
| `/etc/secureforge/manifest.json` | Complete record of every change made |
| `/etc/secureforge/duress/` | Hashed duress passwords for Fake Twin Login |
| `/etc/ssh/sshd_config.d/99-secureforge.conf` | SSH hardening drop-in |
| `/etc/sysctl.d/99-sf-*.conf` | Network and kernel sysctl rules |
| `/etc/modprobe.d/sf-*.conf` | Module blacklists |
| `/etc/fail2ban/jail.d/secureforge.conf` | fail2ban SSH jail |
| `/etc/audit/rules.d/99-secureforge.rules` | auditd comprehensive ruleset |
| `/etc/security/pwquality.conf` | Password quality policy |
| `/etc/security/faillock.conf` | Account lockout policy |
| `/etc/sudoers.d/99-secureforge` | sudo hardening |
| `/etc/profile.d/sf-*.sh` | umask, session timeout, history hardening |
| `/etc/usbguard/` | USBGuard device policy |
| `/etc/endlessh/` | SSH tarpit config |
| `/opt/.canary/` | Canary files |
| `/usr/local/bin/sf-*` | SecureForge helper scripts |
| `/usr/local/bin/secureforge-uninstall` | Hardening uninstaller |

---

## Installation

### Option 1 — Run install.sh (recommended)

```bash
sudo bash install.sh
```

Installs to `/opt/secureforge`, creates `/usr/local/bin/secureforge`, handles Node.js 18+ installation for all supported distros.

### Option 2 — Manual

```bash
git clone https://github.com/D3LTA2033/secureforge
cd secureforge
npm install
sudo node index.js
```

### Option 3 — One-liner (once published)

```bash
curl -fsSL https://raw.githubusercontent.com/D3LTA2033/secureforge/main/install.sh | sudo bash
```

**Requirements:** Node.js 18+, Linux, sudo/root access. `git` and `gcc/make` required for endlessh tarpit module.

---

## Uninstalling

SecureForge has two separate uninstallers:

```bash
# Remove the SecureForge TOOL itself (not the hardening)
sudo secureforge-remove

# Undo the hardening changes SecureForge applied to your system
sudo secureforge-uninstall
```

The hardening uninstaller reads `/etc/secureforge/manifest.json` and:
- Restores backed-up config files
- Removes created files
- Re-enables disabled services

---

## Post-Hardening Checks

After running SecureForge, verify your security posture:

```bash
# Full security audit with scored report
sudo lynis audit system

# Rootkit scan
sudo rkhunter --check

# Check SSH fail2ban jail
sudo fail2ban-client status sshd

# List active audit rules
sudo auditctl -l

# Verify sysctl hardening
sudo sysctl kernel.randomize_va_space kernel.yama.ptrace_scope

# USBGuard device list
sudo usbguard list-devices

# Chrony time sync status
chronyc tracking

# Check canary log
sudo tail -f /var/log/secureforge-canary.log

# View process watchdog log
sudo tail -f /var/log/sf-procguard.log
```

---

## GitHub Version Tracking

On each run, SecureForge hits the GitHub API for the latest release of these tools and shows them before hardening:

| Tool | GitHub Repo |
|------|-------------|
| fail2ban | `fail2ban/fail2ban` |
| lynis | `CISOfy/lynis` |
| rkhunter | `rootkit-hunter/rkhunter` |
| google-authenticator | `google/google-authenticator-libpam` |
| ClamAV | `Cisco-Talos/clamav` |
| Suricata | `OISF/suricata` |
| firehol | `firehol/firehol` |
| auditd | `linux-audit/audit-userspace` |

---

## Project Structure

```
secureforge/
├── index.js                        ← CLI entry point
├── install.sh                      ← System installer
├── package.json
└── src/
    ├── cli/
    │   ├── banner.js               ← ASCII art banner
    │   ├── menu.js                 ← Interactive prompts + maturity warnings
    │   └── runner.js               ← Script executor with ora spinners
    ├── utils/
    │   ├── detect.js               ← Auto-detect distro
    │   ├── github.js               ← Fetch latest package versions
    │   ├── writer.js               ← Write scripts to system + manifest
    │   ├── logger.js               ← Colored logging helpers
    │   └── maturity.js             ← Distro/module stability tracking + warnings
    └── packages/
        ├── shared/                 ← Distro-aware modules used by all distros
        │   ├── pkg.js              ← Package manager + OpenRC/systemd helpers
        │   ├── sysctl.js           ← Shared sysctl fragments
        │   ├── ssh-config.js       ← SSH config generator
        │   ├── usbguard.js         ← USBGuard
        │   ├── ntp.js              ← Chrony NTP hardening
        │   ├── grubpassword.js     ← GRUB bootloader password
        │   ├── crypto.js           ← TLS/crypto policy hardening
        │   ├── ids.js              ← Suricata IDS
        │   ├── acct.js             ← Process accounting
        │   ├── tarpit.js           ← endlessh SSH tarpit
        │   ├── canary.js           ← Canary files with inotify
        │   ├── geofence.js         ← GeoIP login fence
        │   ├── memforge.js         ← Memory/seccomp hardening
        │   └── procguard.js        ← Process watchdog
        ├── arch/                   ← Arch Linux (10 modules + shared)
        ├── debian/                 ← Debian (10 modules + shared)
        ├── ubuntu/                 ← Ubuntu (extends Debian + ubuntu overrides)
        ├── fedora/                 ← Fedora (10 modules + shared)
        ├── rhel/                   ← RHEL (extends Fedora + SCAP + subscription)
        ├── centos/                 ← CentOS (extends Fedora + EPEL + SCAP)
        ├── opensuse/               ← openSUSE (10 modules + shared)
        ├── gentoo/                 ← Gentoo (11 modules + portage.js + shared)
        └── alpine/                 ← Alpine Linux (10 modules + shared)
```

---

## Adding a New Distro

1. Create `src/packages/<distro>/` directory
2. Write module files — each exports:
   ```js
   export default {
     id: 'module-id',
     name: 'Display Name',
     description: 'One line description',
     category: 'Network | Access Control | Kernel | ...',
     maturity: 'stable | beta | alpha | experimental',  // optional
     defaultEnabled: true,
     options: [
       { id: 'opt', type: 'confirm | input | list', label: 'Question?', default: true }
     ],
     generate({ distro, role, exposure, options, versions }) {
       return `bash script string`;
     },
     manifests({ options }) {
       return { backups: [], created: [], disabled_services: [], packages_installed: [] };
     }
   }
   ```
3. Create `src/packages/<distro>/index.js` exporting a `modules` array
4. Add distro to `src/utils/detect.js`, `src/cli/menu.js`, and `index.js`
5. Add maturity level in `src/utils/maturity.js`
6. Add Node.js install method in `install.sh`

---

## Contributing

Pull requests welcome. Before submitting:

- Test changes in a VM (preferably a fresh install of the target distro)
- Run `node index.js --dry-run` to verify script output
- If adding a module, add it to all relevant distro `index.js` files
- Mark new/experimental modules with an appropriate `maturity` field

---

## Disclaimer

SecureForge applies significant system-level changes. While every effort is made to ensure correctness:

- **Test in a VM before running on any production system**
- **Keep a backup or snapshot** before applying hardening
- **Review scripts with `--dry-run`** before applying
- Some modules (particularly Alpha/Experimental) may not work correctly on all system configurations
- The authors take no responsibility for system damage, lockouts, or data loss
- This tool is provided as-is under the MIT license

If you lock yourself out after hardening SSH, you will need console/recovery access to restore from the backup at `/etc/ssh/sshd_config.sf.bak`.

---

## License

**SecureForge Public License v1.0** — See [LICENSE](LICENSE) for full terms.

Key points:
- ✅ Free to use, modify, and distribute
- ✅ Commercial use permitted
- ✅ Security research and CTF use explicitly allowed
- ❌ Cannot use against systems you don't own or aren't authorized to harden
- ❌ Cannot strip stability warnings or disclaimers from distributions
- ❌ Cannot embed in malware or use for offensive operations against third parties

---

<div align="center">

Made with paranoia and good intentions.

*If you found this useful, ⭐ the repo.*

</div>
