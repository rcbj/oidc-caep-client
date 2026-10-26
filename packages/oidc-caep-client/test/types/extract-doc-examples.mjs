// Copies every ```ts block in the documentation into doc-examples/, so `npm run test:types` compiles
// the examples readers copy from: a doc example that no longer matches the API fails the check.
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, '..', '..', '..', '..');
const pages = ['docs/index.md'];
const out = join(here, 'doc-examples');

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });
let count = 0;
for (const page of pages) {
  const text = readFileSync(join(repo, page), 'utf8');
  for (const [, code] of text.matchAll(/^```ts\n([\s\S]*?)^```/gm)) {
    count += 1;
    const name = `${page.replace(/[^a-z0-9]+/gi, '-')}-${count}.ts`;
    writeFileSync(join(out, name), `// Extracted from ${page}; do not edit.\n${code}`);
  }
}
if (!count) throw new Error(`No \`\`\`ts examples found in ${pages.join(', ')}`);
console.log(`extracted ${count} TypeScript example(s)`);
