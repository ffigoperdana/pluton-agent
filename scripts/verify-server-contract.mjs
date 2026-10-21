// Optional maintainer conformance check. Normal build/install/CI needs no server checkout.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
const root = path.resolve(import.meta.dirname, '..');
const index = process.argv.indexOf('--server');
if (index < 0 || !process.argv[index + 1])
  throw Error(
    'Usage: node scripts/verify-server-contract.mjs --server <reviewed-server-checkout>',
  );
const server = path.resolve(process.argv[index + 1]);
const source = JSON.parse(
  fs.readFileSync(path.join(root, 'contracts/extraction-source.json')),
);
const contract = JSON.parse(
  fs.readFileSync(path.join(root, 'contracts/v0.7.0.json')),
);
const revision = execFileSync('git', ['-C', server, 'rev-parse', 'HEAD'], {
  encoding: 'utf8',
  stdio: ['ignore', 'pipe', 'pipe'],
}).trim();
assert.equal(
  revision,
  source.sourceRevision,
  'Server checkout must match reviewed contract revision',
);
for (const entry of source.serverContracts) {
  const bytes = fs
    .readFileSync(path.join(server, entry.file), 'utf8')
    .replace(/\r\n/g, '\n');
  assert.equal(
    crypto.createHash('sha256').update(bytes).digest('hex'),
    entry.sha256,
    'Server contract source drift: ' + entry.file,
  );
}
const require = createRequire(path.join(root, 'agent/package.json')),
  ts = require('typescript');
async function load(relative) {
  const text = fs.readFileSync(path.join(server, relative), 'utf8');
  const compiled = ts.transpileModule(text, {
    compilerOptions: {
      module: ts.ModuleKind.ESNext,
      target: ts.ScriptTarget.ES2022,
    },
  }).outputText;
  return import(
    'data:text/javascript;base64,' + Buffer.from(compiled).toString('base64')
  );
}
const protocol = await load('backend/src/utils/agentProtocol.ts'),
  filters = await load('backend/src/utils/backupExclusions.ts');
const r = contract.request,
  c = contract.command;
assert.equal(
  protocol.signAgentRequest(
    r.secret,
    r.timestamp,
    r.nonce,
    r.method,
    r.path,
    r.body,
  ),
  r.signature,
);
assert.equal(
  protocol.signAgentCommand(
    c.secret,
    c.signatureTimestamp,
    { ...c, leaseExpiresAt: new Date(c.leaseExpiresAt) },
    c.leaseToken,
  ),
  c.signature,
);
for (const v of contract.exclusions) {
  if (!v.accepted) {
    assert.throws(() => filters.parseBackupExclusions(v.input));
    continue;
  }
  assert.deepEqual(filters.parseBackupExclusions(v.input), v.parsed);
  assert.deepEqual(
    filters.sourceResticExclusions('/srv/example-app', v.parsed),
    v.restic,
  );
}
console.log(
  'PASS independent pinned server implementation conformance; no server writes or required build dependency',
);
