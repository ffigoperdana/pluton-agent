import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { sourceArchive, MAX_SOURCE_ARCHIVE_BYTES } from '../lib/source-archive.mjs';

test('release source archive accepts more than 1 MiB and retains an explicit size ceiling', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pluton-source-archive-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const git = (...args) => execFileSync('git', ['-C', root, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
  git('init');
  git('config', 'user.name', 'Synthetic Test');
  git('config', 'user.email', 'test@example.invalid');
  const commit = () => {
    git('add', '--', 'fixture.txt');
    git('commit', '-m', 'Synthetic source fixture');
    return git('rev-parse', 'HEAD').toString().trim();
  };
  fs.writeFileSync(path.join(root, 'fixture.txt'), Buffer.alloc(2 * 1024 * 1024, 0x61));
  const archive = sourceArchive(root, commit(), 'synthetic/');
  assert(archive.length > 1024 * 1024);
  assert(archive.includes(Buffer.from('synthetic/fixture.txt')));
  assert.throws(() => sourceArchive(root, 'not-an-existing-revision', 'synthetic/'));
  fs.writeFileSync(path.join(root, 'fixture.txt'), Buffer.alloc(MAX_SOURCE_ARCHIVE_BYTES + 1024, 0x62));
  assert.throws(() => sourceArchive(root, commit(), 'synthetic/'), { code: 'ENOBUFS' });
});
