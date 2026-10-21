import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
const root = path.resolve(import.meta.dirname, '../..');
test('standalone operator documentation has no missing or escaping local document links', () => {
  const files = [
    'README.md',
    ...fs
      .readdirSync(path.join(root, 'docs'))
      .filter((f) => f.endsWith('.md'))
      .map((f) => 'docs/' + f),
  ];
  for (const file of files)
    for (const match of fs
      .readFileSync(path.join(root, file), 'utf8')
      .matchAll(/\[[^\]]+\]\(([^\s)]+)\)/g)) {
      const link = match[1];
      if (link.startsWith('https://') || link.startsWith('#')) continue;
      const target = path.resolve(root, path.dirname(file), link.split('#')[0]);
      assert(
        target.startsWith(root + path.sep),
        'Link must remain inside standalone repository',
      );
      assert(fs.existsSync(target), `${file}: missing local document link`);
    }
});
