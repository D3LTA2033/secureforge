import ssh           from './ssh.js';
import network       from './network.js';
import kernel        from './kernel.js';
import firewall      from './firewall.js';
import login         from './login.js';
import faketwinlogin from './faketwinlogin.js';
import root          from './root.js';
import audit         from './audit.js';
import filesystem    from './filesystem.js';
import services      from './services.js';
import portage       from './portage.js';

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
  portage,
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
