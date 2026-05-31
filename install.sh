#!/usr/bin/env bash
# SecureForge Installer
set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[x]${NC} $1"; }
info() { echo -e "${CYAN}[i]${NC} $1"; }
sep()  { echo -e "${DIM}$(printf '─%.0s' {1..56})${NC}"; }
die()  { err "$1"; exit 1; }

# ── Config ────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/secureforge"
BIN_LINK="/usr/local/bin/secureforge"
MIN_NODE=18
REPO_URL="https://github.com/yourusername/secureforge"   # update before publishing
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Banner ────────────────────────────────────────────────────────────
clear
echo -e "${RED}"
cat << 'BANNER'
 ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗
 ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝
 ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗
 ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝
 ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗
 ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
BANNER
echo -e "${WHITE}"
cat << 'BANNER2'
 ███████╗ ██████╗ ██████╗  ██████╗ ███████╗
 ██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
 █████╗  ██║   ██║██████╔╝██║  ███╗█████╗
 ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
 ██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
 ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
BANNER2
echo -e "${NC}"
echo -e "  ${DIM}Installer v1.0.0${NC}"
sep
echo

# ── Privilege check ───────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  if command -v sudo &>/dev/null; then
    info "Re-running with sudo..."
    exec sudo bash "$0" "$@"
  else
    die "Run as root or install sudo first."
  fi
fi

# ── Platform check ────────────────────────────────────────────────────
if [[ "$(uname -s)" != "Linux" ]]; then
  die "SecureForge only supports Linux."
fi

# ── Distro detection ──────────────────────────────────────────────────
detect_distro() {
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    ID_LOWER="${ID,,}"
    case "$ID_LOWER" in
      arch|manjaro|endeavouros)    echo "arch" ;;
      ubuntu)                      echo "ubuntu" ;;
      debian)                      echo "debian" ;;
      fedora)                      echo "fedora" ;;
      rhel|"red hat"*)             echo "rhel" ;;
      centos|centos-stream)        echo "centos" ;;
      opensuse*|suse)              echo "opensuse" ;;
      *)
        # Fallback: check ID_LIKE
        case "${ID_LIKE,,}" in
          *arch*)     echo "arch" ;;
          *ubuntu*)   echo "ubuntu" ;;
          *debian*)   echo "debian" ;;
          *fedora*|*rhel*) echo "fedora" ;;
          *suse*)     echo "opensuse" ;;
          *)          echo "unknown" ;;
        esac
        ;;
    esac
  else
    echo "unknown"
  fi
}

DISTRO=$(detect_distro)
info "Detected distro: ${BOLD}${DISTRO}${NC}"

if [[ "$DISTRO" == "unknown" ]]; then
  warn "Unknown distro — will attempt generic Node.js install."
fi

# ── Node.js version check / install ───────────────────────────────────
sep
echo -e "  ${BOLD}Checking Node.js...${NC}"
sep

node_version() {
  node --version 2>/dev/null | grep -oP '\d+' | head -1
}

install_node_arch() {
  log "Installing Node.js via pacman..."
  pacman -Sy --noconfirm nodejs npm
}

install_node_debian() {
  log "Installing Node.js 20.x via NodeSource..."
  apt-get update -qq
  apt-get install -y -qq curl ca-certificates
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y -qq nodejs
}

install_node_fedora() {
  log "Installing Node.js via dnf..."
  dnf module enable -y nodejs:20 2>/dev/null || dnf install -y nodejs npm
}

install_node_rhel() {
  log "Installing Node.js 20.x on RHEL..."
  # Try NodeSource first, then EPEL
  curl -fsSL https://rpm.nodesource.com/setup_20.x | bash - 2>/dev/null || \
    dnf install -y nodejs npm
}

install_node_centos() {
  log "Installing Node.js on CentOS..."
  dnf install -y epel-release 2>/dev/null || true
  dnf module enable -y nodejs:20 2>/dev/null || \
    curl -fsSL https://rpm.nodesource.com/setup_20.x | bash - && dnf install -y nodejs
}

install_node_opensuse() {
  log "Installing Node.js via zypper..."
  zypper install -y -n nodejs20 npm20 2>/dev/null || \
    zypper install -y -n nodejs npm
}

install_node_gentoo() {
  log "Installing Node.js via Portage (emerge)..."
  warn "This compiles Node.js from source on Gentoo — may take a long time."
  # Unmask if needed
  mkdir -p /etc/portage/package.accept_keywords
  echo "net-libs/nodejs ~amd64" >> /etc/portage/package.accept_keywords/nodejs 2>/dev/null || true
  emerge --ask=n net-libs/nodejs
}

install_node_alpine() {
  log "Installing Node.js via apk..."
  # Enable community repo first
  REPOS=/etc/apk/repositories
  if ! grep -q 'community' "$REPOS" 2>/dev/null; then
    MIRROR=$(grep -m1 'http' "$REPOS" 2>/dev/null | sed 's|/v[0-9].*||')
    ALPINE_VER=$(cat /etc/alpine-release 2>/dev/null | cut -d. -f1,2 || echo "3.19")
    echo "${MIRROR}/v${ALPINE_VER}/community" >> "$REPOS"
    apk update -q
  fi
  apk add --no-cache nodejs npm
}

install_node_nvm() {
  log "Installing Node.js via NVM (fallback)..."
  export NVM_DIR="/usr/local/nvm"
  mkdir -p "$NVM_DIR"
  curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | \
    NVM_DIR="$NVM_DIR" bash
  . "$NVM_DIR/nvm.sh"
  nvm install 20
  nvm use 20
  nvm alias default 20
  # Create global symlinks
  NODE_BIN=$(nvm which 20)
  ln -sf "$NODE_BIN" /usr/local/bin/node
  ln -sf "$(dirname "$NODE_BIN")/npm" /usr/local/bin/npm
  ln -sf "$(dirname "$NODE_BIN")/npx" /usr/local/bin/npx
}

CURRENT_NODE=$(node_version 2>/dev/null || echo "0")

if [[ "$CURRENT_NODE" -ge "$MIN_NODE" ]]; then
  log "Node.js v$(node --version) already installed. ✓"
else
  if [[ "$CURRENT_NODE" -gt 0 ]]; then
    warn "Node.js v$(node --version) is too old (need ≥ v${MIN_NODE})."
  else
    warn "Node.js not found."
  fi

  log "Installing Node.js ${MIN_NODE}+..."
  case "$DISTRO" in
    arch)     install_node_arch ;;
    ubuntu|debian) install_node_debian ;;
    fedora)   install_node_fedora ;;
    rhel)     install_node_rhel ;;
    centos)   install_node_centos ;;
    opensuse) install_node_opensuse ;;
    gentoo)   install_node_gentoo ;;
    alpine)   install_node_alpine ;;
    *)        install_node_nvm ;;
  esac

  CURRENT_NODE=$(node_version 2>/dev/null || echo "0")
  if [[ "$CURRENT_NODE" -lt "$MIN_NODE" ]]; then
    die "Node.js install failed or version still < ${MIN_NODE}. Install manually: https://nodejs.org"
  fi
  log "Node.js v$(node --version) installed. ✓"
fi

# ── npm check ─────────────────────────────────────────────────────────
if ! command -v npm &>/dev/null; then
  die "npm not found. Install npm alongside Node.js."
fi
log "npm v$(npm --version) found. ✓"

# ── Determine source directory ─────────────────────────────────────────
sep
echo -e "  ${BOLD}Installing SecureForge...${NC}"
sep

# If we're running from inside the repo, use that. Otherwise clone.
if [[ -f "$SCRIPT_DIR/package.json" ]] && grep -q '"name": "secureforge"' "$SCRIPT_DIR/package.json" 2>/dev/null; then
  SOURCE_DIR="$SCRIPT_DIR"
  log "Using source from: $SOURCE_DIR"
else
  if ! command -v git &>/dev/null; then
    warn "git not found — installing..."
    case "$DISTRO" in
      arch)     pacman -S --noconfirm git ;;
      ubuntu|debian) apt-get install -y -qq git ;;
      fedora|rhel|centos) dnf install -y git ;;
      opensuse) zypper install -y -n git ;;
      *)        die "Please install git manually and re-run." ;;
    esac
  fi
  TMPDIR=$(mktemp -d /tmp/secureforge-install.XXXXXX)
  log "Cloning SecureForge to $TMPDIR..."
  git clone --depth=1 "$REPO_URL" "$TMPDIR" || \
    die "Clone failed. Check your internet connection or URL: $REPO_URL"
  SOURCE_DIR="$TMPDIR"
fi

# ── Install to /opt/secureforge ───────────────────────────────────────
log "Copying to ${INSTALL_DIR}..."

if [[ -d "$INSTALL_DIR" ]]; then
  warn "Existing install found at $INSTALL_DIR — backing up..."
  mv "$INSTALL_DIR" "${INSTALL_DIR}.bak.$(date +%s)"
fi

mkdir -p "$INSTALL_DIR"
cp -r "$SOURCE_DIR"/. "$INSTALL_DIR/"

# ── npm install ───────────────────────────────────────────────────────
log "Installing npm dependencies..."
cd "$INSTALL_DIR"

# Use --omit=dev if supported (npm ≥ 7)
npm install --omit=dev 2>/dev/null || npm install --production 2>/dev/null || npm install

log "Dependencies installed. ✓"

# ── Permissions ───────────────────────────────────────────────────────
chmod 755 "$INSTALL_DIR"
chmod 755 "$INSTALL_DIR/index.js"
chown -R root:root "$INSTALL_DIR"
# Allow all users to read but only root to write
find "$INSTALL_DIR" -type d -exec chmod 755 {} \;
find "$INSTALL_DIR" -type f -exec chmod 644 {} \;
chmod 755 "$INSTALL_DIR/index.js"

# ── Create /usr/local/bin/secureforge wrapper ─────────────────────────
log "Creating system command: secureforge"

cat > "$BIN_LINK" << WRAPPER
#!/usr/bin/env bash
# SecureForge launcher
exec node "${INSTALL_DIR}/index.js" "\$@"
WRAPPER

chmod 755 "$BIN_LINK"
log "Created: $BIN_LINK ✓"

# ── Write uninstall script ────────────────────────────────────────────
UNINSTALL_SCRIPT="/usr/local/bin/secureforge-remove"

cat > "$UNINSTALL_SCRIPT" << 'UNINSTALL'
#!/usr/bin/env bash
set -euo pipefail
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }

if [[ $EUID -ne 0 ]]; then
  exec sudo bash "$0" "$@"
fi

echo -e "${RED}SecureForge Installer Removal${NC}"
echo "This removes the SecureForge TOOL ITSELF (not the hardening it applied)."
echo "To undo system hardening, run: sudo secureforge-uninstall"
echo
read -rp "Remove SecureForge? [y/N] " CONFIRM
[[ "${CONFIRM,,}" != "y" ]] && exit 0

log "Removing /opt/secureforge..."
rm -rf /opt/secureforge

log "Removing /usr/local/bin/secureforge..."
rm -f /usr/local/bin/secureforge

log "Removing this script..."
rm -f /usr/local/bin/secureforge-remove

log "Done. SecureForge removed."
warn "Any hardening previously applied is still active. Run 'sudo secureforge-uninstall' to reverse it."
UNINSTALL

chmod 755 "$UNINSTALL_SCRIPT"
log "Created uninstall script: $UNINSTALL_SCRIPT ✓"

# ── Verify installation ───────────────────────────────────────────────
sep
echo -e "  ${BOLD}Verifying...${NC}"
sep

if secureforge --version &>/dev/null; then
  log "Verification passed. ✓"
else
  warn "Could not verify 'secureforge --version' — checking manually..."
  if node "$INSTALL_DIR/index.js" --version &>/dev/null; then
    log "Node.js execution works. ✓"
  else
    err "Verification failed. Check: node $INSTALL_DIR/index.js --version"
  fi
fi

# ── Done ──────────────────────────────────────────────────────────────
sep
echo
echo -e "  ${GREEN}${BOLD}SecureForge installed successfully!${NC}"
echo
echo -e "  ${BOLD}Usage:${NC}"
echo -e "    ${CYAN}secureforge${NC}               — interactive wizard"
echo -e "    ${CYAN}secureforge --list${NC}         — list all modules"
echo -e "    ${CYAN}secureforge --dry-run${NC}      — preview without changes"
echo -e "    ${CYAN}secureforge --distro rhel${NC}  — skip distro detection"
echo
echo -e "  ${BOLD}Uninstall:${NC}"
echo -e "    ${CYAN}sudo secureforge-remove${NC}    — remove this tool"
echo -e "    ${CYAN}sudo secureforge-uninstall${NC} — undo hardening changes"
echo
sep
