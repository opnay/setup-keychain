import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import { security } from '../src/security.js';

test('command failures expose neither passwords, stderr, nor the raw process error', context => {
  const secret = 'fake-sensitive-password';
  const failure = Object.assign(new Error(`Command failed with ${secret}`), {
    stderr: Buffer.from(`authentication failed for ${secret}`),
    stdout: Buffer.from(secret),
  });
  context.mock.method(childProcess, 'execFileSync', () => { throw failure; });
  assert.throws(() => security(['import', '/private/test.p12', '-P', secret]), error => {
    assert.ok(error instanceof Error);
    assert.equal(error.message, 'macOS security import failed.');
    assert.equal('stderr' in error, false);
    assert.equal('stdout' in error, false);
    assert.equal('cause' in error, false);
    assert.equal(String(error).includes(secret), false);
    return true;
  });
});
