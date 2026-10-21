import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { signRequest, verifyCommand } from '../../agent/dist/protocol.js';
import {
  parseBackupExclusions,
  sourceResticExclusions,
} from '../../agent/dist/backupExclusions.js';
import { parseBackupFilesystemPayload } from '../../agent/dist/backupFilesystem.js';
import { AGENT_VERSION } from '../../agent/dist/inventory.js';
import { validate } from '../validate-standalone.mjs';
const contract = JSON.parse(
  fs.readFileSync(new URL('../../contracts/v0.7.0.json', import.meta.url)),
);
test(
  'standalone extraction has no runtime imports or build paths into the monorepo',
  validate,
);
test('actual server-generated request and command HMAC vectors match unchanged Agent', () => {
  assert.equal(AGENT_VERSION, '0.7.0');
  const r = contract.request;
  assert.equal(
    signRequest(r.secret, r.timestamp, r.nonce, r.method, r.path, r.body),
    r.signature,
  );
  const { secret, ...command } = contract.command;
  assert.equal(verifyCommand(secret, command), true);
  for (const mutation of [
    { payload: { changed: true } },
    { leaseToken: 'replaced' },
    { id: 'other' },
    { leaseExpiresAt: '2000-01-01T00:00:00Z' },
  ])
    assert.equal(verifyCommand(secret, { ...command, ...mutation }), false);
});
test('server-generated exclusion corpus matches acceptance, normalization and exact Restic anchoring', () => {
  for (const v of contract.exclusions) {
    if (!v.accepted) {
      assert.throws(() => parseBackupExclusions(v.input));
      continue;
    }
    assert.deepEqual(parseBackupExclusions(v.input), v.parsed);
    assert.deepEqual(
      sourceResticExclusions('/srv/example-app', v.parsed),
      v.restic,
    );
  }
});
test('versioned backup v4 retains exclusions and refuses newer versions and shell options', () => {
  const v = {
    version: 4,
    backupId: 'backup-01',
    planId: 'plan-01',
    sourcePath: '/srv/example-app',
    excludes: ['.git'],
    repository: {
      remoteName: 'pluton',
      path: 'repositories/app-01',
      initialize: false,
    },
    rclone: {
      type: 'sftp',
      options: {
        host: 'sftp.example.internal',
        user: 'backup_reader',
        pass: 'synthetic-only',
      },
    },
    repositoryPassword: 'synthetic-only-repository-password',
  };
  assert.equal(parseBackupFilesystemPayload(v).version, 4);
  assert.throws(() => parseBackupFilesystemPayload({ ...v, version: 5 }));
  assert.throws(() => parseBackupFilesystemPayload({ ...v, command: 'sh' }));
  assert.throws(() =>
    parseBackupFilesystemPayload({
      ...v,
      rclone: {
        ...v.rclone,
        options: { ...v.rclone.options, ssh: 'unapproved' },
      },
    }),
  );
});
