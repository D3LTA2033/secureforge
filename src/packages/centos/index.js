// CentOS: RHEL base with EPEL-aware network module + CentOS SCAP
import ssh           from '../fedora/ssh.js';
import network       from './network.js';             // CentOS: EPEL + CRB setup
import kernel        from '../fedora/kernel.js';
import firewall      from '../fedora/firewall.js';
import login         from '../fedora/login.js';
import faketwinlogin from '../fedora/faketwinlogin.js';
import root          from '../fedora/root.js';
import audit         from '../fedora/audit.js';
import filesystem    from '../fedora/filesystem.js';
import services      from '../fedora/services.js';
import scap          from './scap.js';

// Deeper security modules (shared, distro-aware)
import usbguard      from '../shared/usbguard.js';
import ntp           from '../shared/ntp.js';
import grubpassword  from '../shared/grubpassword.js';
import crypto        from '../shared/crypto.js';
import ids           from '../shared/ids.js';
import acct          from '../shared/acct.js';
import tarpit        from '../shared/tarpit.js';
import canary        from '../shared/canary.js';
import geofence      from '../shared/geofence.js';
import memforge      from '../shared/memforge.js';
import procguard     from '../shared/procguard.js';

export const modules = [
  ssh,
  network,
  kernel,
  firewall,
  login,
  faketwinlogin,
  root,
  audit,
  filesystem,
  services,
  scap,
  usbguard,
  ntp,
  grubpassword,
  crypto,
  ids,
  acct,
  tarpit,
  canary,
  geofence,
  memforge,
  procguard,
];
