import ora from 'ora';
import chalk from 'chalk';
import { writeScript, runScript, writeManifest, writeUninstaller, ensureSystemDirs } from '../utils/writer.js';
import { fetchLatestVersions } from '../utils/github.js';
import { log, warn, err, sep, info } from '../utils/logger.js';

export async function run(distro, role, exposure, enabledModules, moduleConfigs, allModules) {
  sep();

  // Fetch latest versions from GitHub
  const spinner = ora({ text: 'Fetching latest package versions from GitHub...', color: 'cyan' }).start();
  const versions = await fetchLatestVersions();
  spinner.succeed('Package versions fetched.');

  for (const [pkg, ver] of Object.entries(versions)) {
    if (ver !== 'unknown') info(`${chalk.bold(pkg)}: latest = ${chalk.green('v' + ver)}`);
  }

  sep();

  const manifest = {
    version: '1.0.0',
    distro,
    role,
    exposure,
    modules: enabledModules,
    backups: [],
    created: [],
    disabled_services: [],
    packages_installed: [],
  };

  ensureSystemDirs();

  const total = enabledModules.length;
  let passed  = 0;
  let failed  = 0;

  for (let i = 0; i < enabledModules.length; i++) {
    const id     = enabledModules[i];
    const module = allModules.find(m => m.id === id);
    if (!module) continue;

    const config  = { distro, role, exposure, options: moduleConfigs[id] ?? {}, versions };
    const spinner = ora({ text: `${module.name}...`, color: 'yellow' }).start();

    try {
      const script = module.generate(config);
      const path   = writeScript(id, script);
      const ok     = runScript(path, module.name);

      if (ok) {
        spinner.succeed(chalk.green(`${module.name}`));
        passed++;

        // Collect manifest entries from module
        if (module.manifests) {
          const m = module.manifests(config);
          manifest.backups.push(...(m.backups ?? []));
          manifest.created.push(...(m.created ?? []));
          manifest.disabled_services.push(...(m.disabled_services ?? []));
          manifest.packages_installed.push(...(m.packages_installed ?? []));
        }
      } else {
        spinner.fail(chalk.red(`${module.name} — script error`));
        failed++;
      }
    } catch (e) {
      spinner.fail(chalk.red(`${module.name} — ${e.message}`));
      failed++;
    }
  }

  sep();
  writeManifest(manifest);
  writeUninstaller(manifest);
  sep();

  log(`Done. ${chalk.green(passed + ' succeeded')}, ${failed > 0 ? chalk.red(failed + ' failed') : chalk.dim('0 failed')}.`);
  log(`Uninstall: ${chalk.cyan('sudo secureforge-uninstall')}`);
  log(`Audit:     ${chalk.cyan('sudo lynis audit system')}`);
  warn('Reboot recommended to apply all kernel/mount changes.');
}
