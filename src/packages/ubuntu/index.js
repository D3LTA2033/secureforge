import ssh           from '../debian/ssh.js';
import network       from '../debian/network.js';
import kernel        from '../debian/kernel.js';
import firewall      from '../debian/firewall.js';
import login         from '../debian/login.js';
import faketwinlogin from './faketwinlogin.js';
import root          from '../debian/root.js';
import audit         from '../debian/audit.js';
import filesystem    from '../debian/filesystem.js';
import services      from './services.js';

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
