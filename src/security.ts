import { execFileSync } from 'node:child_process';

export type Security = (args: string[]) => string;

// Never expose stderr or command arguments: they may contain passwords.
export const security: Security = (args) => {
  try {
    return execFileSync('/usr/bin/security', args, {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 30_000,
    });
  } catch {
    throw new Error(`macOS security ${args[0]} failed.`);
  }
};

export function paths(output: string): string[] {
  return output.split('\n').map(line => line.trim()).filter(Boolean).map(line => {
    if (!line.startsWith('"') || !line.endsWith('"')) throw new Error('Unexpected keychain path output.');
    // security uses quoted C strings for paths.
    return JSON.parse(line) as string;
  });
}
