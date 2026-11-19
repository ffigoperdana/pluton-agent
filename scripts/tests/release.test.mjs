import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { verifyRelease } from '../verify-release.mjs';
test('release checksum verification rejects corruption, traversal, duplicates and invalid source identity', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-release-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const files = ['example-source.tar.gz', 'example-app.tar.gz'];
  for (const f of files)
    fs.writeFileSync(path.join(root, f), 'synthetic archive');
  const m = {
    format: 1,
    version: 'v0.7.0',
    sourceCommit: 'a'.repeat(40),
    platform: 'linux-x64',
    artifacts: files.map((file) => ({
      file,
      sha256: crypto
        .createHash('sha256')
        .update('synthetic archive')
        .digest('hex'),
    })),
  };
  const write = (value) =>
    fs.writeFileSync(
      path.join(root, 'release-manifest.json'),
      JSON.stringify(value),
    );
  write(m);
  verifyRelease(root);
  fs.appendFileSync(path.join(root, files[0]), 'corruption');
  assert.throws(() => verifyRelease(root), /checksum/);
  fs.writeFileSync(path.join(root, files[0]), 'synthetic archive');
  for (const bad of [
    { ...m, sourceCommit: 'main' },
    {
      ...m,
      artifacts: [
        { ...m.artifacts[0], file: '../outside.tar.gz' },
        m.artifacts[1],
      ],
    },
    { ...m, artifacts: [m.artifacts[0], m.artifacts[0]] },
  ]) {
    write(bad);
    assert.throws(() => verifyRelease(root));
  }
});

test('release identity accepts the 0.8 and 0.9 series and refuses unsupported versions', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-release-version-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const files = ['example-source.tar.gz', 'example-app.tar.gz'];
  for (const f of files) fs.writeFileSync(path.join(root, f), 'synthetic archive');
  const sha256 = crypto.createHash('sha256').update('synthetic archive').digest('hex');
  const manifest = (version) => ({
    format: 1,
    version,
    sourceCommit: 'a'.repeat(40),
    platform: 'linux-x64',
    artifacts: files.map((file) => ({ file, sha256 })),
  });
  for (const accepted of ['v0.8.0', 'v0.9.0']) {
    fs.writeFileSync(path.join(root, 'release-manifest.json'), JSON.stringify(manifest(accepted)));
    assert.equal(verifyRelease(root).version, accepted);
  }
  for (const version of ['v0.10.0', 'v1.0.0', '0.9.0', 'v0.6.0']) {
    fs.writeFileSync(path.join(root, 'release-manifest.json'), JSON.stringify(manifest(version)));
    assert.throws(() => verifyRelease(root), /release identity/);
  }
});
