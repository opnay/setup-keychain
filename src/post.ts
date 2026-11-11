import * as core from '@actions/core';
import { cleanup, runnerTemp } from './managed.js';
import { security } from './security.js';
try {
  const keychain = core.getState('keychain');
  if (keychain) cleanup(runnerTemp(), keychain, security);
} catch (error) { core.setFailed(error instanceof Error ? error.message : 'Cleanup failed.'); }
