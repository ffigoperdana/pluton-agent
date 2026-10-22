import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

test('explicit independent baseline rejects runtime drift, unversioned additions and extraction changes', () => {
  const root = path.resolve(import.meta.dirname, '../..');
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'pluton-source-baseline-'));
  try {
    for (const file of ['package.json', 'pnpm-workspace.yaml', 'agent/package.json', 'agent/tsconfig.json',
      'contracts/extraction-source.json', 'contracts/standalone-source-v1.json', 'scripts/validate-standalone.mjs']) {
      fs.mkdirSync(path.dirname(path.join(scratch, file)), { recursive: true });
      fs.copyFileSync(path.join(root, file), path.join(scratch, file));
    }
    fs.cpSync(path.join(root, 'agent/src'), path.join(scratch, 'agent/src'), { recursive: true });
    const run = () => spawnSync(process.execPath, [path.join(scratch, 'scripts/validate-standalone.mjs')], { encoding: 'utf8' });
    assert.equal(run().status, 0);
    const transport = path.join(scratch, 'agent/src/transport.ts');
    const original = fs.readFileSync(transport);
    fs.appendFileSync(transport, '\n// unversioned synthetic change\n');
    assert.notEqual(run().status, 0);
    fs.writeFileSync(transport, original);
    const unexpected = path.join(scratch, 'agent/src/unreviewed.ts');
    fs.writeFileSync(unexpected, 'export const unreviewed = true;\n');
    assert.notEqual(run().status, 0);
    fs.unlinkSync(unexpected);
    fs.appendFileSync(path.join(scratch, 'contracts/extraction-source.json'), '\n');
    assert.notEqual(run().status, 0);
  } finally { fs.rmSync(scratch, { recursive: true, force: true }); }
});
