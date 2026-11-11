import { build } from 'esbuild';
for (const entry of ['setup', 'import', 'post']) {
  await build({ entryPoints: [`src/${entry}.ts`], outfile: `dist/${entry}/index.js`, bundle: true, platform: 'node', target: 'node24', format: 'cjs', legalComments: 'external' });
}
