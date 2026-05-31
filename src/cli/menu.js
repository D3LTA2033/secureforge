import inquirer from 'inquirer';
import chalk from 'chalk';
import { detectDistro } from '../utils/detect.js';
import { LEVEL_BADGE, distroMaturity, moduleMaturity, printDistroWarning } from '../utils/maturity.js';

const DISTROS = [
  { name: 'Arch Linux',  value: 'arch' },
  { name: 'Debian',      value: 'debian' },
  { name: 'Ubuntu',      value: 'ubuntu' },
  { name: 'Fedora',      value: 'fedora' },
  { name: 'openSUSE',    value: 'opensuse' },
  { name: 'RHEL 8/9',        value: 'rhel' },
  { name: 'CentOS / Stream', value: 'centos' },
  { name: 'Gentoo',          value: 'gentoo' },
  { name: 'Alpine Linux',    value: 'alpine' },
];

const ROLES = [
  { name: 'Web Server',         value: 'web_server' },
  { name: 'Database Server',    value: 'database_server' },
  { name: 'Dev Machine',        value: 'dev_machine' },
  { name: 'VPN Gateway',        value: 'vpn_gateway' },
  { name: 'Generic / Desktop',  value: 'generic' },
];

const EXPOSURES = [
  { name: 'Internal only (LAN / VPN)',   value: 'internal' },
  { name: 'Internet-facing (public IP)', value: 'internet' },
];

export async function askDistro() {
  const detected = detectDistro();

  if (detected) {
    const label    = DISTROS.find(d => d.value === detected)?.name ?? detected;
    const maturity = distroMaturity(detected);
    const badge    = LEVEL_BADGE[maturity.level];
    const { confirm } = await inquirer.prompt([{
      type: 'confirm',
      name: 'confirm',
      message: `Detected ${chalk.cyan(label)} ${badge} — use this distro?`,
      default: true,
    }]);
    if (confirm) {
      printDistroWarning(detected);
      if (maturity.level !== 'stable') {
        const { proceed } = await inquirer.prompt([{
          type: 'confirm',
          name: 'proceed',
          message: 'Proceed anyway?',
          default: false,
        }]);
        if (!proceed) process.exit(0);
      }
      return detected;
    }
  }

  const choices = DISTROS.map(d => {
    const m = distroMaturity(d.value);
    return { name: `${d.name}  ${LEVEL_BADGE[m.level]}`, value: d.value };
  });

  const { distro } = await inquirer.prompt([{
    type: 'list',
    name: 'distro',
    message: 'Select your distro:',
    choices,
  }]);

  printDistroWarning(distro);
  const m = distroMaturity(distro);
  if (m.level !== 'stable') {
    const { proceed } = await inquirer.prompt([{
      type: 'confirm',
      name: 'proceed',
      message: 'Proceed anyway?',
      default: false,
    }]);
    if (!proceed) process.exit(0);
  }

  return distro;
}

export async function askRole() {
  const { role } = await inquirer.prompt([{
    type: 'list',
    name: 'role',
    message: 'What is this machine\'s role?',
    choices: ROLES,
  }]);
  return role;
}

export async function askExposure() {
  const { exposure } = await inquirer.prompt([{
    type: 'list',
    name: 'exposure',
    message: 'Network exposure:',
    choices: EXPOSURES,
  }]);
  return exposure;
}

export async function askModules(modules) {
  const choices = modules.map(m => {
    const level = moduleMaturity(m.id);
    const badge = level !== 'stable' ? ` ${LEVEL_BADGE[level]}` : '';
    return {
      name: `${chalk.bold(m.name)}${badge} ${chalk.dim('— ' + m.description)}`,
      value: m.id,
      checked: m.defaultEnabled ?? false,
    };
  });

  const { selected } = await inquirer.prompt([{
    type: 'checkbox',
    name: 'selected',
    message: 'Select modules to apply (space to toggle, a to toggle all):',
    choices,
    pageSize: 20,
  }]);

  return selected;
}

export async function askModuleOptions(module) {
  if (!module.options?.length) return {};

  console.log();
  console.log(chalk.bold.yellow(`  Options for: ${module.name}`));

  const answers = {};

  for (const opt of module.options) {
    if (opt.type === 'confirm') {
      const res = await inquirer.prompt([{
        type: 'confirm',
        name: opt.id,
        message: `  ${opt.label}`,
        default: opt.default ?? false,
      }]);
      answers[opt.id] = res[opt.id];

    } else if (opt.type === 'input') {
      const res = await inquirer.prompt([{
        type: opt.secret ? 'password' : 'input',
        name: opt.id,
        message: `  ${opt.label}`,
        default: opt.default ?? '',
        validate: opt.validate ?? (() => true),
      }]);
      answers[opt.id] = res[opt.id];

    } else if (opt.type === 'list') {
      const res = await inquirer.prompt([{
        type: 'list',
        name: opt.id,
        message: `  ${opt.label}`,
        choices: opt.choices,
        default: opt.default,
      }]);
      answers[opt.id] = res[opt.id];
    }
  }

  return answers;
}

export async function askFakeTwinConfig() {
  console.log();
  console.log(chalk.bold.red('  Fake Twin Login (Duress / Decoy OS)'));
  console.log(chalk.dim('  Two passwords for your account — one opens the real OS, one opens a decoy.'));
  console.log();

  const answers = await inquirer.prompt([
    {
      type: 'input',
      name: 'decoyUser',
      message: '  Decoy username (will be created):',
      default: 'sf_decoy',
      validate: v => /^[a-z_][a-z0-9_-]{2,31}$/.test(v) || 'Invalid username',
    },
    {
      type: 'password',
      name: 'decoyPassword',
      message: '  Duress password (entering this → decoy session):',
      validate: v => v.length >= 8 || 'Min 8 characters',
    },
    {
      type: 'confirm',
      name: 'alertWebhook',
      message: '  Alert via webhook when duress password is used?',
      default: false,
    },
    {
      type: 'input',
      name: 'webhookUrl',
      message: '  Webhook URL:',
      when: a => a.alertWebhook,
      validate: v => v.startsWith('http') || 'Must be a valid URL',
    },
    {
      type: 'confirm',
      name: 'populateDecoy',
      message: '  Populate decoy home with convincing fake files?',
      default: true,
    },
    {
      type: 'confirm',
      name: 'logDecoyAccess',
      message: '  Log duress logins to syslog?',
      default: true,
    },
  ]);

  return answers;
}

export async function confirmPlan(plan) {
  console.log();
  console.log(chalk.bold('  Hardening Plan:'));
  console.log(`  ${chalk.cyan('Distro')}   : ${chalk.white(plan.distro)}`);
  console.log(`  ${chalk.cyan('Role')}     : ${chalk.white(plan.role)}`);
  console.log(`  ${chalk.cyan('Exposure')} : ${chalk.white(plan.exposure)}`);
  console.log(`  ${chalk.cyan('Modules')}  : ${plan.modules.join(', ')}`);
  console.log();
  console.log(chalk.bold.red('  WARNING: This will make system-level changes requiring sudo.'));
  console.log();

  const { go } = await inquirer.prompt([{
    type: 'confirm',
    name: 'go',
    message: 'Apply hardening now?',
    default: false,
  }]);

  return go;
}
