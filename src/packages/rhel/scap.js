export default {
  id: 'scap',
  name: 'OpenSCAP Compliance',
  description: 'SCAP Security Guide scanning + STIG/CIS remediation (RHEL official profiles)',
  category: 'Compliance',
  defaultEnabled: false,

  options: [
    { id: 'profile',     type: 'list',    label: 'Compliance profile to scan against:', default: 'cis',
      choices: [
        { name: 'CIS RHEL Benchmark — Level 1',              value: 'cis' },
        { name: 'CIS RHEL Benchmark — Level 2 (strict)',     value: 'cis_server_l2' },
        { name: 'DISA STIG (US Dept of Defense)',            value: 'stig' },
        { name: 'NIST 800-171 (CUI protection)',             value: 'cui' },
        { name: 'PCI-DSS v4',                                value: 'pci-dss' },
        { name: 'ANSSI BP-028 High (French gov standard)',   value: 'anssi_bp28_high' },
      ]
    },
    { id: 'remediate',   type: 'confirm', label: 'AUTO-REMEDIATE failing rules? (recommended: scan first)', default: false },
    { id: 'htmlReport',  type: 'confirm', label: 'Generate HTML compliance report?',                        default: true },
    { id: 'scheduleScan',type: 'confirm', label: 'Schedule weekly SCAP scan via cron?',                     default: true },
  ],

  generate({ distro, options }) {
    const profile    = options.profile     ?? 'cis';
    const remediate  = options.remediate   ?? false;
    const htmlRep    = options.htmlReport  ?? true;
    const schedule   = options.scheduleScan ?? true;
    const rhelVer    = distro === 'rhel' ? '' : 'centos';

    return `
# ── OpenSCAP Compliance (${distro.toUpperCase()}) ──────────────────────────────────
dnf install -y openscap-scanner scap-security-guide openscap-utils

# Find the RHEL/CentOS SSG datastream
SSG_PATH=""
for f in \
  /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml \
  /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml \
  /usr/share/xml/scap/ssg/content/ssg-centos9-ds.xml \
  /usr/share/xml/scap/ssg/content/ssg-centos8-ds.xml \
  /usr/share/xml/scap/ssg/content/ssg-rhel-ds.xml; do
  [ -f "$f" ] && SSG_PATH="$f" && break
done

if [ -z "$SSG_PATH" ]; then
  echo "[!] No SSG datastream found. Install scap-security-guide."
  exit 1
fi

echo "[+] Using SSG: $SSG_PATH"
echo "[+] Profile: ${profile}"

REPORT_DIR=/etc/secureforge/scap-reports
mkdir -p "$REPORT_DIR"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
RESULTS="$REPORT_DIR/results-${profile}-$TIMESTAMP.xml"
${htmlRep ? `REPORT="$REPORT_DIR/report-${profile}-$TIMESTAMP.html"` : ''}

# Run the scan
oscap xccdf eval \\
  --profile xccdf_org.ssgproject.content_profile_${profile} \\
  --results "$RESULTS" \\
  ${htmlRep ? `--report "$REPORT" \\` : ''} \
  --fetch-remote-resources \\
  "$SSG_PATH" 2>&1 | tee /etc/secureforge/scap-last-scan.log

SCAN_EXIT=$?
if [ $SCAN_EXIT -eq 2 ]; then
  echo "[!] Scan completed with failures — see report for details."
elif [ $SCAN_EXIT -eq 0 ]; then
  echo "[+] All rules PASSED."
fi

${htmlRep ? `
echo "[+] HTML report: $REPORT"
` : ''}

${remediate ? `
echo "[!] Running AUTO-REMEDIATION for profile: ${profile}"
echo "[!] This will modify system configuration to meet the profile requirements."
oscap xccdf eval \\
  --profile xccdf_org.ssgproject.content_profile_${profile} \\
  --remediate \\
  --results "$REPORT_DIR/remediation-results-$TIMESTAMP.xml" \\
  "$SSG_PATH" 2>&1 | tee /etc/secureforge/scap-remediation.log
echo "[+] Remediation complete. Review /etc/secureforge/scap-remediation.log"
` : `
echo "[i] Remediation not run. To remediate:"
echo "    oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_${profile} --remediate $SSG_PATH"
`}

${schedule ? `
cat > /etc/cron.weekly/sf-scap-scan << SCANSCHED
#!/bin/bash
TIMESTAMP=\$(date +%Y%m%d)
SSG_PATH="$SSG_PATH"
oscap xccdf eval \\
  --profile xccdf_org.ssgproject.content_profile_${profile} \\
  --results /etc/secureforge/scap-reports/weekly-\$TIMESTAMP.xml \\
  ${htmlRep ? `--report /etc/secureforge/scap-reports/weekly-\$TIMESTAMP.html \\` : ''} \
  "\$SSG_PATH" > /var/log/scap-weekly.log 2>&1
logger -t secureforge-scap "Weekly SCAP scan complete — profile: ${profile}"
SCANSCHED
chmod 755 /etc/cron.weekly/sf-scap-scan
` : ''}
`;
  },

  manifests({ options }) {
    return {
      created: [
        '/etc/secureforge/scap-reports/',
        ...(options.scheduleScan ? ['/etc/cron.weekly/sf-scap-scan'] : []),
      ],
      packages_installed: ['openscap-scanner', 'scap-security-guide'],
    };
  },
};
