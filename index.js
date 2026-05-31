#!/usr/bin/env node
import { program } from 'commander';
import chalk from 'chalk';
import { printBanner } from './src/cli/banner.js';
import {
  askDistro, askRole, askExposure,
  askModules, askModuleOptions, askFakeTwinConfig, confirmPlan,
} from './src/cli/menu.js';
import { run } from './src/cli/runner.js';
import { isRoot, hasSudo } from './src/utils/detect.js';

program
  .name('secureforge')
  .description('Interactive Linux OS hardening wizard')
  .version('1.0.0')
  .option('--dry-run', 'Show what would be done without making changes')
  .option('--list',    'List all available modules and exit')
  .option('--distro <distro>', 'Skip distro detection (arch|debian|ubuntu)')
  .option('--yes',     'Skip confirmation prompt');

program.parse();
const opts = program.opts();

async function loadModules(distro) {
  const { modules } = await import(`./src/packages/${distro}/index.js`);
  return modules;
}

async function main() {
  printBanner();

  // Auth check
  if (!isRoot() && !hasSudo()) {
    console.log(chalk.red('[x] sudo access is required to run SecureForge.'));
    process.exit(1);
  }

  // Distro
  const distro = opts.distro ?? await askDistro();
  const validDistros = ['arch', 'debian', 'ubuntu', 'fedora', 'opensuse', 'rhel', 'centos', 'gentoo', 'alpine'];
  if (!validDistros.includes(distro)) {
    console.log(chalk.red(`[x] Unknown distro: ${distro}. Use: ${validDistros.join(', ')}`));
    process.exit(1);
  }

  const allModules = await loadModules(distro);

  // --list flag
  if (opts.list) {
    console.log(chalk.bold('\nAvailable modules:\n'));
    for (const m of allModules) {
      const status = m.defaultEnabled ? chalk.green('on ') : chalk.dim('off');
      console.log(`  [${status}] ${chalk.bold(m.id.padEnd(18))} ${chalk.dim(m.description)}`);
    }
    console.log();
    process.exit(0);
  }

  const role     = await askRole();
  const exposure = await askExposure();

  // Module selection
  const selectedIds = await askModules(allModules);

  if (selectedIds.length === 0) {
    console.log(chalk.yellow('\n[!] No modules selected. Exiting.'));
    process.exit(0);
  }

  // Gather per-module options
  const moduleConfigs = {};

  for (const id of selectedIds) {
    const module = allModules.find(m => m.id === id);
    if (!module) continue;

    // Special case: faketwinlogin uses its own dedicated flow
    if (id === 'faketwinlogin') {
      moduleConfigs[id] = await askFakeTwinConfig();
    } else if (module.options?.length) {
      moduleConfigs[id] = await askModuleOptions(module);
    } else {
      moduleConfigs[id] = {};
    }
  }

  // Confirm
  if (!opts.yes) {
    const go = await confirmPlan({ distro, role, exposure, modules: selectedIds });
    if (!go) {
      console.log(chalk.yellow('\n[!] Aborted.'));
      process.exit(0);
    }
  }

  if (opts.dryRun) {
    console.log(chalk.cyan('\n[i] Dry run — showing generated scripts:\n'));
    for (const id of selectedIds) {
      const module = allModules.find(m => m.id === id);
      if (!module) continue;
      const script = module.generate({ distro, role, exposure, options: moduleConfigs[id] ?? {}, versions: {} });
      console.log(chalk.bold(`\n── ${module.name} ──`));
      console.log(chalk.dim(script));
    }
    process.exit(0);
  }

  await run(distro, role, exposure, selectedIds, moduleConfigs, allModules);
}

main().catch(e => {
  console.error(chalk.red(`\n[x] Fatal: ${e.message}`));
  process.exit(1);
});
