const fs = require('node:fs');
const cp = require('node:child_process');
const assert = require('node:assert/strict');
const snapshot = JSON.parse(fs.readFileSync(process.env.STATE_baseline, 'utf8'));
assert.equal(cp.execFileSync('/usr/bin/security', ['list-keychains', '-d', 'user'], { encoding: 'utf8' }), snapshot.search);
assert.equal(cp.execFileSync('/usr/bin/security', ['default-keychain', '-d', 'user'], { encoding: 'utf8' }), snapshot.default);
assert.deepEqual(fs.readdirSync(process.env.RUNNER_TEMP).filter(n => n.startsWith('setup-keychain-')), snapshot.dirs);
fs.unlinkSync(process.env.STATE_baseline);
console.log('Verified reverse post cleanup, original search/default, and removal of managed state.');
