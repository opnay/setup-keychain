import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { cleanup, create, importIdentity, readState, runnerTemp } from '../src/managed.js';
import { paths, Security } from '../src/security.js';

process.env.GITHUB_RUN_ID = 'test-run';
process.env.GITHUB_RUN_ATTEMPT = '1';
process.env.GITHUB_JOB = 'unit';

// This adapter models the observable OS boundary, not PKCS12 or codesign correctness.
function fixture() {
  const temp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'keychain-test-')));
  let search = ['/original/login.keychain-db'];
  let defaultKeychain = search[0];
  let fail = '';
  const identities = new Map<string, string[]>();
  const calls: string[][] = [];
  const run: Security = args => {
    calls.push(args);
    if (args[0] === fail) { fail = ''; throw new Error('Injected OS failure'); }
    const last = args.at(-1)!;
    switch (args[0]) {
      case 'list-keychains':
        if (args[3] === '-s') search = args.slice(4);
        else return search.map(p => JSON.stringify(p)).join('\n');
        break;
      case 'default-keychain':
        if (args[3] === '-s') defaultKeychain = last;
        else return JSON.stringify(defaultKeychain);
        break;
      case 'create-keychain':
        fs.writeFileSync(last, '', { mode: 0o644 });
        search.push(last); // macOS can add the keychain while creating it.
        identities.set(last, []);
        break;
      case 'delete-keychain':
        fs.unlinkSync(last); identities.delete(last); break;
      case 'import':
        identities.get(args[3])!.push(fs.readFileSync(args[1], 'utf8')); break;
    }
    return '';
  };
  return { temp, run, calls, identities, search: () => search, defaultKeychain: () => defaultKeychain,
    fail: (command: string) => { fail = command; }, dispose: () => fs.rmSync(temp, { recursive: true, force: true }) };
}

test('nested setup preserves search/default and reverse cleanup restores each snapshot', () => {
  const f = fixture();
  try {
    let saved = '';
    const first = create(f.temp, true, f.run, key => { saved = key; });
    assert.equal(saved, first.keychain);
    assert.equal(fs.statSync(first.keychain).mode & 0o777, 0o600);
    const second = create(f.temp, false, f.run, () => {});
    assert.notEqual(first.keychain, second.keychain);
    assert.notEqual(first.password, second.password);
    assert.equal(f.defaultKeychain(), first.keychain);
    assert.deepEqual(f.search(), ['/original/login.keychain-db', first.keychain, second.keychain]);
    cleanup(f.temp, second.keychain, f.run);
    assert.deepEqual(f.search(), ['/original/login.keychain-db', first.keychain]);
    cleanup(f.temp, first.keychain, f.run);
    cleanup(f.temp, first.keychain, f.run);
    assert.equal(f.defaultKeychain(), '/original/login.keychain-db');
    assert.deepEqual(fs.readdirSync(f.temp), []);
  } finally { f.dispose(); }
});

for (const command of ['create-keychain', 'set-keychain-settings', 'unlock-keychain', 'list-keychains', 'default-keychain']) {
  test(`setup failure at ${command} restores state and removes owned files`, () => {
    const f = fixture();
    try {
      // Fail only after the snapshot has been captured.
      assert.throws(() => create(f.temp, true, f.run, () => f.fail(command)));
      assert.deepEqual(f.search(), ['/original/login.keychain-db']);
      assert.equal(f.defaultKeychain(), '/original/login.keychain-db');
      assert.deepEqual(fs.readdirSync(f.temp), []);
    } finally { f.dispose(); }
  });
}

test('cleanup tries independent operations and retains state for retry', () => {
  const f = fixture();
  try {
    const state = create(f.temp, true, f.run, () => {});
    f.fail('default-keychain');
    assert.throws(() => cleanup(f.temp, state.keychain, f.run), /default restoration/);
    assert.equal(fs.existsSync(state.keychain), false);
    assert.deepEqual(f.search(), ['/original/login.keychain-db']);
    assert.equal(readState(f.temp, state.keychain).keychain, state.keychain);
    cleanup(f.temp, state.keychain, f.run);
    assert.equal(f.defaultKeychain(), '/original/login.keychain-db');
    assert.deepEqual(fs.readdirSync(f.temp), []);
  } finally { f.dispose(); }
});

test('two imports preserve source and prior identities; failed partition update only removes temporary copy', () => {
  const f = fixture();
  try {
    const state = create(f.temp, false, f.run, () => {});
    const source = path.join(f.temp, 'source.p12');
    fs.writeFileSync(source, 'first');
    importIdentity(f.temp, state.keychain, source, '', 'first-password', f.run);
    importIdentity(f.temp, state.keychain, '', Buffer.from('second').toString('base64'), ' p a s s ', f.run);
    f.fail('set-key-partition-list');
    assert.throws(() => importIdentity(f.temp, state.keychain, source, '', 'bad', f.run));
    assert.equal(fs.readFileSync(source, 'utf8'), 'first');
    assert.deepEqual(f.identities.get(state.keychain), ['first', 'second', 'first']);
    assert.deepEqual(fs.readdirSync(path.dirname(state.keychain)).sort(), ['signing.keychain-db', 'state.json']);
    assert.ok(f.calls.some(args => args[0] === 'import' && args[7] === 'first-password'));
    assert.equal(f.defaultKeychain(), '/original/login.keychain-db');
    cleanup(f.temp, state.keychain, f.run);
    assert.equal(fs.readFileSync(source, 'utf8'), 'first');
  } finally { f.dispose(); }
});

test('input errors and import command failure leave no transient certificate files', () => {
  const f = fixture();
  try {
    const state = create(f.temp, false, f.run, () => {});
    for (const [file, encoded] of [['', ''], ['x', 'eA=='], ['', '%%%'], ['', 'YQ=']]) {
      assert.throws(() => importIdentity(f.temp, state.keychain, file, encoded, 'password', f.run));
    }
    const before = f.calls.length;
    assert.throws(() => importIdentity(f.temp, state.keychain, '', 'eA==', '', f.run), /must be nonempty/);
    assert.equal(f.calls.length, before);
    f.fail('import');
    assert.throws(() => importIdentity(f.temp, state.keychain, '', 'eA==', 'password', f.run));
    assert.deepEqual(fs.readdirSync(path.dirname(state.keychain)).sort(), ['signing.keychain-db', 'state.json']);
    assert.deepEqual(f.identities.get(state.keychain), []);
  } finally { f.dispose(); }
});

test('reject unmanaged paths, traversal, symlinks, open permissions and another job', () => {
  const f = fixture();
  try {
    const state = create(f.temp, false, f.run, () => {});
    assert.throws(() => readState(f.temp, '/original/login.keychain-db'));
    assert.throws(() => readState(f.temp, `${path.dirname(state.keychain)}/../signing.keychain-db`));
    const file = path.join(path.dirname(state.keychain), 'state.json');
    fs.chmodSync(file, 0o644);
    assert.throws(() => readState(f.temp, state.keychain), /unsafe/);
    fs.chmodSync(file, 0o600);
    const content = fs.readFileSync(file);
    fs.unlinkSync(file); fs.symlinkSync('/dev/null', file);
    assert.throws(() => readState(f.temp, state.keychain), /unsafe/);
    fs.unlinkSync(file); fs.writeFileSync(file, content, { mode: 0o600 });
    const edited = JSON.parse(content.toString()); edited.job = 'another-job';
    fs.writeFileSync(file, JSON.stringify(edited));
    assert.throws(() => readState(f.temp, state.keychain), /Invalid managed/);
  } finally { f.dispose(); }
});

test('parse quoted paths with spaces and reject unexpected OS output', () => {
  assert.deepEqual(paths('    "/a path/login.keychain-db"\n'), ['/a path/login.keychain-db']);
  assert.throws(() => paths('unexpected'));
});

test('platform and runner environment are required', () => {
  const previous = process.env.RUNNER_TEMP;
  delete process.env.RUNNER_TEMP;
  try { assert.throws(runnerTemp, /macOS|RUNNER_TEMP/); }
  finally { if (previous !== undefined) process.env.RUNNER_TEMP = previous; }
});
