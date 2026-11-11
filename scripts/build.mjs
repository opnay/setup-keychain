import { build } from 'esbuild';
import { readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';

rmSync('dist', { recursive: true, force: true });
const packages = new Set();
for (const entry of ['setup', 'import', 'post']) {
  const result = await build({ entryPoints: [`src/${entry}.ts`], outfile: `dist/${entry}/index.js`, bundle: true, platform: 'node', target: 'node24', format: 'cjs', legalComments: 'external', metafile: true });
  for (const input of Object.keys(result.metafile.inputs)) {
    const match = input.match(/^node_modules\/((?:@[^/]+\/)?[^/]+)/);
    if (match) packages.add(match[1]);
  }
}
let notices = '# Third-party notices\n\nLicenses for packages included in the generated bundles.\n';
for (const name of [...packages].sort()) {
  const root = `node_modules/${name}`;
  const manifest = JSON.parse(readFileSync(`${root}/package.json`, 'utf8'));
  const license = readdirSync(root).find(file => /^license(?:\.md|\.txt)?$/i.test(file));
  if (!license) throw new Error(`Missing license for ${name}`);
  notices += `\n## ${name} ${manifest.version}\n\n${readFileSync(`${root}/${license}`, 'utf8').trim()}\n`;
}
writeFileSync('dist/THIRD_PARTY_NOTICES.md', notices);
