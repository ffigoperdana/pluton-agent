import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

test('Ubuntu version diagnostics drain output and preserve producer failures under pipefail', {
  skip: process.platform !== 'linux',
}, () => {
  const root = path.resolve(import.meta.dirname, '../..');
  const lines = fs.readFileSync(path.join(root, 'tests/ubuntu/fresh-install.sh'), 'utf8').split('\n');
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'pluton-version-output-'));
  try {
    const producer = path.join(scratch, 'producer.sh');
    // Delayed output larger than a pipe deterministically exposes an early
    // reader exit; small real version output only fails under some schedules.
    fs.writeFileSync(producer, `#!/bin/bash
set -e
printf '%s\\n' 'synthetic version 1.75.1'
sleep 0.05
dd if=/dev/zero bs=65536 count=4 2>/dev/null
exit "$1"
`);
    for (const prefix of ['ldd --version', '/opt/pluton-agent/bin/rclone version']) {
      const line = lines.find((value) => value.startsWith(prefix + ' |'));
      assert.ok(line, `Missing actual diagnostic pipeline: ${prefix}`);
      const command = 'bash "$1" "$2"' + line.slice(prefix.length);
      const run = (code) => spawnSync('/bin/bash', ['-Eeuo', 'pipefail', '-c', command,
        'version-output-test', producer, String(code)], { encoding: 'utf8', timeout: 5000 });
      const success = run(0);
      assert.ifError(success.error);
      assert.equal(success.status, 0, `${prefix}: ${success.stderr}`);
      assert.equal(success.stdout, 'synthetic version 1.75.1\n');
      const failure = run(42);
      assert.ifError(failure.error);
      assert.equal(failure.status, 42, `${prefix}: upstream failure must not be masked`);
    }
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
});
