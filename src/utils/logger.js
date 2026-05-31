import chalk from 'chalk';

export const log   = (msg) => console.log(`${chalk.green('[+]')} ${msg}`);
export const warn  = (msg) => console.log(`${chalk.yellow('[!]')} ${msg}`);
export const err   = (msg) => console.log(`${chalk.red('[x]')} ${msg}`);
export const info  = (msg) => console.log(`${chalk.cyan('[i]')} ${msg}`);
export const sep   = ()    => console.log(chalk.dim('─'.repeat(50)));
export const step  = (n, total, msg) => console.log(`${chalk.bold.cyan(`[${n}/${total}]`)} ${msg}`);
