import { writeFileSync, mkdirSync, existsSync, readFileSync } from 'fs';
import { execSync, spawnSync } from 'child_process';
import { join } from 'path';
import { log, warn, err, sep } from './logger.js';

const SF_DIR     = '/etc/secureforge';
const MANIFEST   = `${SF_DIR}/manifest.json`;
const LIB_DIR    = '/usr/local/lib/secureforge';
const UNINSTALL  = '/usr/local/bin/secureforge-uninstall';

export function ensureSystemDirs() {
  for (const dir of [SF_DIR, LIB_DIR]) {
    execSync(`sudo mkdir -p ${dir}`);
    execSync(`sudo chmod 700 ${dir}`);
  }
}

export function writeManifest(data) {
  const json = JSON.stringify(data, null, 2);
  const tmp  = `/tmp/sf-manifest-${Date.now()}.json`;
  writeFileSync(tmp, json);
  execSync(`sudo mv ${tmp} ${MANIFEST}`);
  execSync(`sudo chmod 600 ${MANIFEST}`);
}

export function readManifest() {
  try {
    const raw = execSync(`sudo cat ${MANIFEST}`, { encoding: 'utf8' });
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export function writeScript(name, content) {
  const tmp = `/tmp/sf-${name}-${Date.now()}.sh`;
  writeFileSync(tmp, `#!/usr/bin/env bash\nset -euo pipefail\n\n${content}`);
  execSync(`chmod +x ${tmp}`);
  return tmp;
}

export function runScript(scriptPath, label) {
  log(`Running: ${label}`);
  const result = spawnSync('sudo', ['bash', scriptPath], {
    stdio: 'inherit',
    encoding: 'utf8',
  });

  if (result.status !== 0) {
    err(`Script failed: ${label} (exit ${result.status})`);
    return false;
  }
  return true;
}

export function writeUninstaller(manifest) {
  const lines = ['#!/usr/bin/env bash', 'set -euo pipefail', ''];
  lines.push(`RED='\\033[0;31m'; GREEN='\\033[0;32m'; YELLOW='\\033[1;33m'; NC='\\033[0m'`);
  lines.push(`log()  { echo -e "\${GREEN}[+]\${NC} \$1"; }`);
  lines.push(`warn() { echo -e "\${YELLOW}[!]\${NC} \$1"; }`);
  lines.push(`err()  { echo -e "\${RED}[x]\${NC} \$1"; }`);
  lines.push('');
  lines.push('if [[ $EUID -ne 0 ]]; then err "Run as root"; exit 1; fi');
  lines.push('');
  lines.push('echo "SecureForge Uninstaller"');
  lines.push('read -p "This will REMOVE all SecureForge hardening. Continue? [y/N] " CONFIRM');
  lines.push('[[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]] && exit 0');
  lines.push('');

  // Restore backed-up files
  if (manifest.backups?.length) {
    lines.push('log "Restoring config backups..."');
    for (const bak of manifest.backups) {
      lines.push(`[ -f "${bak.backup}" ] && cp "${bak.backup}" "${bak.original}" && log "Restored: ${bak.original}"`);
    }
  }

  // Remove created files
  if (manifest.created?.length) {
    lines.push('log "Removing created files..."');
    for (const f of manifest.created) {
      lines.push(`rm -f "${f}" && log "Removed: ${f}"`);
    }
  }

  // Re-enable disabled services
  if (manifest.disabled_services?.length) {
    lines.push('log "Re-enabling services..."');
    for (const svc of manifest.disabled_services) {
      lines.push(`systemctl enable --now ${svc} 2>/dev/null || warn "Could not re-enable: ${svc}"`);
    }
  }

  // Remove secureforge dirs
  lines.push('log "Removing SecureForge system files..."');
  lines.push(`rm -rf ${SF_DIR} ${LIB_DIR}`);
  lines.push(`rm -f ${UNINSTALL}`);
  lines.push('');
  lines.push('log "Uninstall complete. Reboot recommended."');

  const content = lines.join('\n') + '\n';
  const tmp = `/tmp/sf-uninstall-${Date.now()}.sh`;
  writeFileSync(tmp, content);
  execSync(`sudo mv ${tmp} ${UNINSTALL}`);
  execSync(`sudo chmod 755 ${UNINSTALL}`);
  log(`Uninstall script written → ${UNINSTALL}`);
}
