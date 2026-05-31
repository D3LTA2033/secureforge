export default {
  id: 'firewall',
  name: 'Firewall',
  description: 'firewalld zones, role-based ports, rate limiting',
  category: 'Network',
  defaultEnabled: true,

  options: [
    { id: 'defaultZone',  type: 'list',    label: 'Default firewalld zone:', default: 'drop',
      choices: [
        { name: 'drop (strictest)',              value: 'drop' },
        { name: 'block (reject with ICMP)',      value: 'block' },
        { name: 'public (standard)',             value: 'public' },
      ]
    },
    { id: 'sshRateLimit', type: 'confirm', label: 'Rate-limit SSH connections?',  default: true },
    { id: 'denyPing',     type: 'confirm', label: 'Block external ICMP ping?',    default: false },
    { id: 'logDropped',   type: 'confirm', label: 'Log dropped packets?',         default: true },
    { id: 'customPorts',  type: 'input',   label: 'Extra open ports (e.g. 8080):', default: '' },
  ],

  generate({ role, exposure, options }) {
    const zone        = options.defaultZone  ?? 'drop';
    const rateLimit   = options.sshRateLimit ?? true;
    const denyPing    = options.denyPing     ?? false;
    const logDropped  = options.logDropped   ?? true;
    const customPorts = (options.customPorts ?? '').split(',').map(p => p.trim()).filter(Boolean);

    const isWeb  = role === 'web_server';
    const isVPN  = role === 'vpn_gateway';
    const internet = exposure === 'internet';

    return `
# ── Firewall: firewalld (openSUSE) ────────────────────────────────────
zypper install -y -n firewalld

systemctl enable --now firewalld

firewall-cmd --set-default-zone=${zone}
firewall-cmd --permanent --add-service=ssh

${isWeb ? `
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
` : ''}

${isVPN ? `
firewall-cmd --permanent --add-service=openvpn
firewall-cmd --permanent --add-port=1194/udp
` : ''}

${customPorts.map(p => `firewall-cmd --permanent --add-port=${p}/tcp`).join('\n')}

${denyPing ? `
firewall-cmd --permanent --add-icmp-block=echo-request
firewall-cmd --permanent --add-icmp-block=echo-reply
` : ''}

${logDropped ? `firewall-cmd --permanent --set-log-denied=all` : ''}

firewall-cmd --reload

${rateLimit ? `
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT_direct 0 \
  -p tcp --dport 22 -m state --state NEW -m recent --set
firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT_direct 1 \
  -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 6 -j DROP
firewall-cmd --reload
` : ''}

firewall-cmd --list-all
`;
  },

  manifests() {
    return { packages_installed: ['firewalld'] };
  },
};
