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
import {
  deriveCommandSecretsKey,
  openSealedCommandSecrets,
} from '../../agent/dist/sealedSecrets.js';
import { validate } from '../validate-standalone.mjs';
const contract = JSON.parse(
  fs.readFileSync(new URL('../../contracts/v0.7.0.json', import.meta.url)),
);
const s3Contract = JSON.parse(
  fs.readFileSync(new URL('../../contracts/v0.8.0.json', import.meta.url)),
);
test(
  'standalone extraction has no runtime imports or build paths into the monorepo',
  validate,
);
test('Agent 0.9.0 retains the original 0.7.0 server request and command HMAC vectors', () => {
  assert.equal(AGENT_VERSION, '0.9.0');
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
  assert.equal(parseBackupFilesystemPayload({ ...v, sourceDiagnosticsVersion: 1 }).sourceDiagnosticsVersion, 1);
  assert.throws(() => parseBackupFilesystemPayload({ ...v, sourceDiagnosticsVersion: 2 }));
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
test('Agent 0.8.0 S3 stage 1 vectors: capabilities request, version 5 command HMAC and sealed secrets', () => {
  const r = s3Contract.request;
  assert.equal(
    signRequest(r.secret, r.timestamp, r.nonce, r.method, r.path, r.body),
    r.signature,
  );
  assert.deepEqual(JSON.parse(r.body).capabilities, {
    backupExclusionsVersion: 1,
    repositoryBackends: ['sftp', 's3'],
    backupPayloadVersion: 5,
  });
  const { secret, ...command } = s3Contract.command;
  assert.equal(verifyCommand(secret, command), true);
  const sealedField = command.payload.sealed;
  const tampered = Buffer.from(sealedField.ciphertext, 'base64');
  tampered[0] ^= 1;
  assert.equal(
    verifyCommand(secret, {
      ...command,
      payload: {
        ...command.payload,
        sealed: { ...sealedField, ciphertext: tampered.toString('base64') },
      },
    }),
    false,
  );
  const s = s3Contract.sealing;
  assert.equal(deriveCommandSecretsKey(s.secret).toString('hex'), s.derivedKeyHex);
  const context = { secret: s.secret, commandId: s.commandId, leaseToken: s.leaseToken };
  assert.deepEqual(sealedField, {
    alg: 'A256GCM',
    kid: s.info,
    nonce: s.nonce,
    ciphertext: s.ciphertext,
    tag: s.tag,
  });
  assert.deepEqual(openSealedCommandSecrets(sealedField, context), JSON.parse(s.plaintext));
  assert.equal(command.id, s.commandId);
  assert.equal(command.leaseToken, s.leaseToken);
  assert.equal(secret, s.secret);
  const parsed = parseBackupFilesystemPayload(command.payload, context);
  assert.equal(parsed.version, 5);
  assert.equal(parsed.rclone.type, 's3');
  assert.equal(parsed.rclone.options.access_key_id, 'SYNTHETICKEY01');
  assert.equal(parsed.rclone.options.secret_access_key, 'synthetic-secret-key-01');
  assert.equal(parsed.repositoryPassword, 'synthetic-repository-password-01');
  assert.deepEqual(parsed.excludes, ['.git']);
  assert.equal(parsed.sourceDiagnosticsVersion, 1);
  assert.throws(() =>
    parseBackupFilesystemPayload(command.payload, { ...context, leaseToken: 'f'.repeat(48) }),
  );
  assert.throws(() =>
    parseBackupFilesystemPayload(command.payload, { ...context, commandId: 'cmd-synthetic-02' }),
  );
});
