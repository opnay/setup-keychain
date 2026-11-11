import * as core from '@actions/core';
import { importIdentity, runnerTemp } from './managed.js';
import { security } from './security.js';
try {
  const password = core.getInput('certificate-password', { trimWhitespace: false });
  const base64 = core.getInput('certificate-base64', { trimWhitespace: false });
  if (password) core.setSecret(password);
  if (base64) core.setSecret(base64);
  importIdentity(runnerTemp(), core.getInput('keychain-path', { required: true }), core.getInput('certificate-path'), base64, password, security);
} catch (error) { core.setFailed(error instanceof Error ? error.message : 'Import failed.'); }
