const fs = require('node:fs');
const cp = require('node:child_process');
const path = require('node:path');
const snapshot = {
  search: cp.execFileSync('/usr/bin/security', ['list-keychains', '-d', 'user'], { encoding: 'utf8' }),
  default: cp.execFileSync('/usr/bin/security', ['default-keychain', '-d', 'user'], { encoding: 'utf8' }),
  dirs: fs.readdirSync(process.env.RUNNER_TEMP).filter(n => n.startsWith('setup-keychain-')),
};
const file = path.join(process.env.RUNNER_TEMP, 'cleanup-baseline.json');
fs.writeFileSync(file, JSON.stringify(snapshot), { mode: 0o600 });
fs.appendFileSync(process.env.GITHUB_STATE, `baseline=${file}\n`);
