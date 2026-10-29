import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import { CommandStatusError } from '../../agent/dist/commandStatus.js';
import { toBackupFilesystemError } from '../../agent/dist/backupFilesystem.js';
import { AgentClient } from '../../agent/dist/client.js';
const contract = JSON.parse(fs.readFileSync(new URL('../../contracts/post-dump-v1.json', import.meta.url)));

test('PR #53 closed completion diagnostics remain compatible without provider text', () => {
  for (const code of contract.statusFailureCodes) {
    for (const stage of contract.failureStages) {
      const error = toBackupFilesystemError(new CommandStatusError(code), stage);
      assert.equal(error.stage, stage);
      assert.equal(error.code, code);
      assert.equal(error.databaseId, undefined);
      assert.equal(error.sourceDiagnostics, undefined);
    }
    assert.equal(toBackupFilesystemError(new CommandStatusError(code), 'database-dump').stage, 'command-status-check');
  }
});

test('PR #53 optional lease deadline and legacy cancellation-only status both work', async () => {
  const identity = { agentId: 'agent-01', deviceId: 'device-01', secret: 'synthetic-contract-only', pollIntervalSeconds: 5, completedCommands: [] };
  for (const result of contract.statusResults) {
    const client = new AgentClient({ serverUrl: new URL('https://example.internal'), dataDir: 'unused', allowedRoots: [], allowInsecureHttp: false }, identity, {
      post: async () => ({ success: true, result }),
    });
    assert.deepEqual(await client.commandStatus('command-01', 'a'.repeat(32)), { cancelled: result.cancelled });
  }
});
