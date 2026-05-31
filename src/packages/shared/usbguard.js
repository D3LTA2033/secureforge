import { pm, pkg } from './pkg.js';

export default {
  id: 'usbguard',
  name: 'USBGuard',
  description: 'Whitelist authorized USB devices — block everything else at kernel level',
  category: 'Hardware',
  defaultEnabled: false,

  options: [
    { id: 'whitelistCurrent', type: 'confirm', label: 'Whitelist all currently connected USB devices?', default: true },
    { id: 'allowHID',         type: 'confirm', label: 'Always allow HID devices (keyboard/mouse)?',     default: true },
    { id: 'allowMassStorage', type: 'confirm', label: 'Allow USB mass storage (flash drives)?',         default: false },
    { id: 'blockNewOnLock',   type: 'confirm', label: 'Block new USB devices when screen is locked?',   default: true },
    { id: 'alertOnBlock',     type: 'confirm', label: 'Log blocked device attempts to syslog?',         default: true },
  ],

  generate({ distro, options }) {
    const whitelistCurrent = options.whitelistCurrent ?? true;
    const allowHID         = options.allowHID         ?? true;
    const allowMassStorage = options.allowMassStorage ?? false;
    const blockOnLock      = options.blockNewOnLock   ?? true;
    const alert            = options.alertOnBlock     ?? true;

    return `
# ── USBGuard (${distro}) ───────────────────────────────────────────────
${pm(distro)(pkg(distro, 'usbguard'))}

# Generate initial policy from currently connected devices
${whitelistCurrent ? `
usbguard generate-policy > /etc/usbguard/rules.conf
chmod 600 /etc/usbguard/rules.conf
` : `
# Start with deny-all policy
echo 'allow id *:* with-interface equals { 00:00:00 }' > /etc/usbguard/rules.conf
chmod 600 /etc/usbguard/rules.conf
`}

${allowHID ? `
# Allow HID (keyboard, mouse) — append if not already whitelisted
if ! grep -q 'allow.*03:01\|allow.*03:02' /etc/usbguard/rules.conf 2>/dev/null; then
  echo 'allow with-interface one-of { 03:*:* }  # HID devices' >> /etc/usbguard/rules.conf
fi
` : ''}

${allowMassStorage ? `
# Allow USB mass storage
echo 'allow with-interface one-of { 08:*:* }  # Mass storage' >> /etc/usbguard/rules.conf
` : `
# Block mass storage explicitly
echo 'reject with-interface one-of { 08:*:* }  # Block mass storage' >> /etc/usbguard/rules.conf
`}

# USBGuard daemon config
cat > /etc/usbguard/usbguard-daemon.conf << 'USBCFG'
RuleFile=/etc/usbguard/rules.conf
ImplicitPolicyTarget=block
PresentDevicePolicy=apply-policy
PresentControllerPolicy=keep
InsertedDevicePolicy=apply-policy
RestoreControllerDeviceState=false
DeviceManagerBackend=uevent
IPCAllowedUsers=root
IPCAllowedGroups=usbguard
${blockOnLock ? 'DeviceInsertedNotify=true' : ''}
${alert ? 'AuditBackend=LinuxAudit' : ''}
USBCFG

# Add admins to usbguard group for device management
groupadd -f usbguard
getent passwd | awk -F: '$3>=1000 && $3<65534 {print $1}' | head -3 | \
  xargs -I{} usermod -aG usbguard {} 2>/dev/null || true

systemctl enable --now usbguard

${alert ? `
# Audit rule to log USBGuard events
mkdir -p /etc/audit/rules.d
echo '-w /dev/bus/usb -p wa -k usb_device' >> /etc/audit/rules.d/99-secureforge.rules 2>/dev/null || true
` : ''}

echo "[+] USBGuard active. Run 'usbguard list-devices' to see connected devices."
echo "[!] Run 'usbguard allow-device <id>' to authorize a new device."
`;
  },

  manifests() {
    return {
      created: ['/etc/usbguard/rules.conf', '/etc/usbguard/usbguard-daemon.conf'],
      packages_installed: ['usbguard'],
    };
  },
};
