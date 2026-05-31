import debianServices from '../debian/services.js';

export default {
  ...debianServices,
  name: 'Service Hardening',
  description: 'Disable risky services, snap audit, whoopsie/apport, systemd hardening',

  options: [
    ...debianServices.options,
    { id: 'disableWhoopsie', type: 'confirm', label: 'Disable Ubuntu crash reporter (whoopsie/apport)?', default: true },
    { id: 'auditSnaps',      type: 'confirm', label: 'Audit snap packages for classic confinement?',     default: true },
    { id: 'disableLivepatch',type: 'confirm', label: 'Skip Canonical Livepatch (use manual patching)?',  default: false },
  ],

  generate(config) {
    const base               = debianServices.generate(config);
    const disableWhoopsie    = config.options.disableWhoopsie ?? true;
    const auditSnaps         = config.options.auditSnaps      ?? true;

    return `${base}

# ── Ubuntu-specific service hardening ─────────────────────────────────
${disableWhoopsie ? `
systemctl disable --now whoopsie apport 2>/dev/null || true
apt-get remove -y -qq whoopsie apport 2>/dev/null || true
` : ''}

${auditSnaps ? `
# Audit snap packages for classic (less-sandboxed) confinement
echo "=== Snap Classic Confinement Audit ===" >> /etc/secureforge/snap-audit.txt
snap list 2>/dev/null | awk 'NR>1 {print $1}' | while read -r pkg; do
  CONF=$(snap info "$pkg" 2>/dev/null | grep 'confinement' | awk '{print $2}')
  if [ "$CONF" = "classic" ]; then
    echo "[!] CLASSIC confinement: $pkg" | tee -a /etc/secureforge/snap-audit.txt
  fi
done
` : ''}
`;
  },

  manifests(config) {
    const base = debianServices.manifests(config);
    const disableWhoopsie = config.options.disableWhoopsie ?? true;
    return {
      ...base,
      disabled_services: [...(base.disabled_services ?? []), ...(disableWhoopsie ? ['whoopsie', 'apport'] : [])],
      created: [...(base.created ?? []), ...(config.options.auditSnaps ? ['/etc/secureforge/snap-audit.txt'] : [])],
    };
  },
};
