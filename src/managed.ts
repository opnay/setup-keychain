import * as fs from 'node:fs';
import * as path from 'node:path';
import { randomBytes } from 'node:crypto';
import { Security, paths } from './security.js';

export interface State {
  version: 1;
  keychain: string;
  password: string;
  search: string[];
  defaultKeychain: string;
  setDefault: boolean;
  job: string;
}

export function runnerTemp(): string {
  if (process.platform !== 'darwin') throw new Error('This action requires macOS.');
  if (!process.env.RUNNER_TEMP) throw new Error('RUNNER_TEMP is required.');
  return fs.realpathSync(process.env.RUNNER_TEMP);
}

function job(): string {
  return ['GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_JOB'].map(key => {
    const value = process.env[key];
    if (!value) throw new Error(`${key} is required.`);
    return value;
  }).join(':');
}

function privateEntry(file: string, directory: boolean, requirePrivate = true): void {
  const stat = fs.lstatSync(file);
  if (stat.isSymbolicLink() || (directory ? !stat.isDirectory() : !stat.isFile()) ||
      stat.uid !== process.getuid?.() || (requirePrivate && (stat.mode & 0o077) !== 0) || (!directory && stat.nlink !== 1)) {
    throw new Error('Managed state has unsafe ownership, permissions, or file type.');
  }
}

export function readState(temp: string, keychain: string): State {
  const dir = path.dirname(keychain);
  if (path.dirname(dir) !== temp || !/^setup-keychain-[A-Za-z0-9]+$/.test(path.basename(dir)) ||
      path.basename(keychain) !== 'signing.keychain-db' || path.resolve(keychain) !== keychain) {
    throw new Error('Only managed keychains under RUNNER_TEMP are supported.');
  }
  privateEntry(dir, true);
  const file = path.join(dir, 'state.json');
  privateEntry(file, false);
  const state = JSON.parse(fs.readFileSync(file, 'utf8')) as State;
  if (state.version !== 1 || state.keychain !== keychain || state.job !== job() ||
      !/^[a-f0-9]{64}$/.test(state.password) || !Array.isArray(state.search) ||
      !state.search.every(p => typeof p === 'string' && path.isAbsolute(p)) ||
      typeof state.defaultKeychain !== 'string' || !path.isAbsolute(state.defaultKeychain) ||
      typeof state.setDefault !== 'boolean') throw new Error('Invalid managed keychain state.');
  return state;
}

export function create(temp: string, setDefault: boolean, run: Security, register: (keychain: string) => void): State {
  const search = paths(run(['list-keychains', '-d', 'user']));
  const defaults = paths(run(['default-keychain', '-d', 'user']));
  if (defaults.length !== 1) throw new Error('Exactly one existing user default keychain is required.');
  const identity = job();
  const dir = fs.mkdtempSync(path.join(temp, 'setup-keychain-'));
  fs.chmodSync(dir, 0o700);
  const state: State = { version: 1, keychain: path.join(dir, 'signing.keychain-db'), password: randomBytes(32).toString('hex'), search, defaultKeychain: defaults[0], setDefault, job: identity };
  try {
    fs.writeFileSync(path.join(dir, 'state.json'), JSON.stringify(state), { mode: 0o600, flag: 'wx' });
    register(state.keychain);
  } catch (error) {
    fs.rmSync(dir, { recursive: true, force: true });
    throw error;
  }
  try {
    run(['create-keychain', '-p', state.password, state.keychain]);
    privateEntry(state.keychain, false, false);
    fs.chmodSync(state.keychain, 0o600);
    run(['set-keychain-settings', '-lut', '21600', state.keychain]);
    run(['unlock-keychain', '-p', state.password, state.keychain]);
    run(['list-keychains', '-d', 'user', '-s', ...search, state.keychain]);
    if (setDefault) run(['default-keychain', '-d', 'user', '-s', state.keychain]);
    return state;
  } catch (error) {
    try { cleanup(temp, state.keychain, run); }
    catch { throw new Error('Setup failed and cleanup is incomplete; post will retry using retained state.'); }
    throw error;
  }
}

export function cleanup(temp: string, keychain: string, run: Security): void {
  if (!fs.existsSync(path.dirname(keychain))) return;
  const state = readState(temp, keychain);
  const failures: string[] = [];
  const attempt = (label: string, fn: () => void) => { try { fn(); } catch { failures.push(label); } };
  // Restore independently, even if one operation fails. Keep state for a retry.
  if (state.setDefault) attempt('default restoration', () => { run(['default-keychain', '-d', 'user', '-s', state.defaultKeychain]); });
  attempt('search restoration', () => { run(['list-keychains', '-d', 'user', '-s', ...state.search]); });
  attempt('keychain deletion', () => {
    if (fs.existsSync(keychain)) {
      privateEntry(keychain, false, false);
      run(['delete-keychain', keychain]);
    }
  });
  if (failures.length) throw new Error(`Cleanup incomplete: ${failures.join(', ')}. Managed state retained for retry.`);
  const remaining = fs.readdirSync(path.dirname(keychain));
  if (remaining.some(name => name !== 'state.json')) throw new Error('Unexpected managed directory contents; state retained for inspection.');
  fs.rmSync(path.join(path.dirname(keychain), 'state.json'));
  // Do not recursively delete unexpected files.
  fs.rmdirSync(path.dirname(keychain));
}

export function importIdentity(temp: string, keychain: string, file: string, base64: string, password: string, run: Security): void {
  if (Boolean(file) === Boolean(base64)) throw new Error('Provide exactly one of certificate-path or certificate-base64.');
  const state = readState(temp, keychain);
  privateEntry(keychain, false);
  let bytes: Buffer;
  if (file) bytes = fs.readFileSync(file);
  else {
    const encoded = base64.replace(/\s/g, '');
    if (!encoded || encoded.length % 4 !== 0 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) throw new Error('Invalid certificate-base64.');
    bytes = Buffer.from(encoded, 'base64');
  }
  if (!bytes.length) throw new Error('Certificate content is empty.');
  const copy = path.join(path.dirname(keychain), `import-${randomBytes(12).toString('hex')}.p12`);
  try {
    fs.writeFileSync(copy, bytes, { mode: 0o600, flag: 'wx' });
    run(['unlock-keychain', '-p', state.password, keychain]);
    run(['import', copy, '-k', keychain, '-f', 'pkcs12', '-P', password, '-T', '/usr/bin/codesign', '-T', '/usr/bin/security']);
    run(['set-key-partition-list', '-S', 'apple-tool:,apple:,codesign:', '-s', '-k', state.password, keychain]);
  } finally {
    bytes.fill(0);
    fs.rmSync(copy, { force: true });
  }
}
