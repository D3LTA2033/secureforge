import rhelScap from '../rhel/scap.js';

// CentOS SCAP: identical to RHEL — SSG ships CentOS-specific datastreams
export default {
  ...rhelScap,
  name: 'OpenSCAP Compliance',
  description: 'SCAP Security Guide scanning + CIS/STIG remediation (CentOS Stream profiles)',

  generate(config) {
    // RHEL generate() already searches for centos datastream paths — reuse it
    return rhelScap.generate({ ...config, distro: 'centos' });
  },
};
