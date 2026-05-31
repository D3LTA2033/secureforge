import chalk from 'chalk';

// Per-distro maturity level
export const DISTRO_MATURITY = {
  arch:     { level: 'stable',      label: 'Stable',      color: 'green'  },
  debian:   { level: 'stable',      label: 'Stable',      color: 'green'  },
  ubuntu:   { level: 'stable',      label: 'Stable',      color: 'green'  },
  fedora:   { level: 'stable',      label: 'Stable',      color: 'green'  },
  rhel:     { level: 'beta',        label: 'Beta',        color: 'yellow' },
  centos:   { level: 'beta',        label: 'Beta',        color: 'yellow' },
  opensuse: { level: 'beta',        label: 'Beta',        color: 'yellow' },
  gentoo:   { level: 'alpha',       label: 'Alpha',       color: 'red'    },
  alpine:   { level: 'alpha',       label: 'Alpha',       color: 'red'    },
};

// Per-module maturity level (defaults to 'stable' if not listed)
export const MODULE_MATURITY = {
  tarpit:    'experimental',
  canary:    'experimental',
  geofence:  'beta',
  memforge:  'beta',
  procguard: 'beta',
  scap:      'beta',
  ids:       'beta',
  usbguard:  'beta',
};

export const LEVEL_BADGE = {
  stable:       chalk.green('✓ Stable'),
  beta:         chalk.yellow('⚠ Beta'),
  alpha:        chalk.red('⚡ Alpha'),
  experimental: chalk.magenta('🧪 Experimental'),
};

export const LEVEL_ORDER = { stable: 0, beta: 1, alpha: 2, experimental: 3 };

export function distroMaturity(distro) {
  return DISTRO_MATURITY[distro] ?? { level: 'beta', label: 'Beta', color: 'yellow' };
}

export function moduleMaturity(id) {
  return MODULE_MATURITY[id] ?? 'stable';
}

export function printDistroWarning(distro) {
  const m = distroMaturity(distro);
  if (m.level === 'stable') return;

  console.log();

  if (m.level === 'alpha') {
    console.log(chalk.bgRed.white.bold('  ⚡  ALPHA DISTRO SUPPORT  ⚡  '));
    console.log(chalk.red([
      '',
      `  ${chalk.bold(distro.toUpperCase())} support is in EARLY DEVELOPMENT.`,
      '  Scripts are untested on many configurations and may:',
      '    • Fail silently or partially apply',
      '    • Use incorrect package names for your version',
      '    • Break services if your setup differs from defaults',
      '',
      '  ALWAYS test in a VM first. Use --dry-run to review scripts.',
      '  You proceed at your own risk.',
      '',
    ].join('\n')));
  } else if (m.level === 'beta') {
    console.log(chalk.bgYellow.black.bold('  ⚠  BETA DISTRO SUPPORT  ⚠  '));
    console.log(chalk.yellow([
      '',
      `  ${chalk.bold(distro.toUpperCase())} support is in BETA.`,
      '  Most features work but edge cases may fail.',
      '  Review output carefully and test in a VM first.',
      '',
    ].join('\n')));
  }
}

export function printModuleWarning(module) {
  const level = moduleMaturity(module.id);
  if (level === 'stable') return;
  if (level === 'experimental') {
    console.log(chalk.magenta(`  [🧪 EXPERIMENTAL] ${module.name} — may not work on all systems`));
  } else if (level === 'beta') {
    console.log(chalk.yellow(`  [⚠ BETA] ${module.name} — test in a VM first`));
  }
}
