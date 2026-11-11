import * as core from '@actions/core';
import { cleanup, create, runnerTemp } from './managed.js';
import { security } from './security.js';
let keychain: string | undefined;
let temp: string | undefined;
try {
  const input = core.getInput('set-default') || 'false';
  if (!['true', 'false'].includes(input)) throw new Error('set-default must be true or false.');
  temp = runnerTemp();
  const state = create(temp, input === 'true', security, keychain => core.saveState('keychain', keychain));
  keychain = state.keychain;
  core.setSecret(state.password);
  core.setOutput('keychain-path', state.keychain);
  core.exportVariable('SETUP_KEYCHAIN_PATH', state.keychain);
} catch (error) {
  if (keychain && temp) {
    try { cleanup(temp, keychain, security); }
    catch { core.error('Cleanup incomplete; post will retry.'); }
  }
  core.setFailed(error instanceof Error ? error.message : 'Setup failed.');
}
