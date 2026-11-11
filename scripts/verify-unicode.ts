import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { cleanup, create, State } from '../src/managed.js';
import { paths, security } from '../src/security.js';

// Real mutations are restricted to disposable GitHub-hosted macOS runners.
if (process.platform !== 'darwin' || process.env.RUNNER_ENVIRONMENT !== 'github-hosted') {
  throw new Error('This integration check requires a disposable GitHub-hosted macOS runner.');
}
const search = security(['list-keychains', '-d', 'user']);
const defaultKeychain = security(['default-keychain', '-d', 'user']);
const root = fs.mkdtempSync(path.join(process.env.RUNNER_TEMP!, 'unicode-test-'));
const temp = path.join(root, '\uD0A4\uCCB4\uC778 space');
fs.mkdirSync(temp);
const states: State[] = [];
try {
  states.push(create(temp, true, security, () => {}));
  const output = security(['list-keychains', '-d', 'user']);
  console.log(`Observed non-ASCII path output: ${JSON.stringify(output)}`);
  assert.ok(paths(output).includes(states[0].keychain));
  states.push(create(temp, true, security, () => {}));
  assert.equal(paths(security(['default-keychain', '-d', 'user']))[0], states[1].keychain);
} finally {
  const errors: unknown[] = [];
  for (const state of states.reverse()) {
    try { cleanup(temp, state.keychain, security); } catch (error) { errors.push(error); }
  }
  if (errors.length) throw new AggregateError(errors, 'Integration cleanup failed.');
  fs.rmdirSync(temp);
  fs.rmdirSync(root);
  assert.equal(security(['list-keychains', '-d', 'user']), search);
  assert.equal(security(['default-keychain', '-d', 'user']), defaultKeychain);
}
console.log('Verified non-ASCII nested keychain paths and exact restoration.');
