import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';

test('security runtime pins agree across installer, upgrade, packaging and CI without changing Agent/dependency contracts', () => {
  const root = path.resolve(import.meta.dirname, '../..');
  const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');
  const runtime = createRequire(import.meta.url)('../../installers/lib/upgrade-runtime.cjs');
  const installer = read('installers/install-agent.sh');
  assert.equal(runtime.TARGET_NODE, 'v22.23.4');
  assert.equal(runtime.ARCHIVE_SHA256, '1805bcd35e6815559bd2eb97db438d3fdb0eb3a5e6a977b7c1badca76337e9ce');
  assert.ok(installer.includes(`readonly NODE_VERSION='${runtime.TARGET_NODE}'`));
  assert.ok(installer.includes(`readonly NODE_LINUX_AMD64_SHA256='${runtime.ARCHIVE_SHA256}'`));
  assert.deepEqual([...runtime.SUPPORTED_NODES], ['v22.18.0', 'v22.23.4']);
  assert.ok(read('scripts/package-release.mjs').includes(`node: '${runtime.TARGET_NODE}'`));
  assert.ok(read('.github/workflows/ci.yml').includes("node-version: '22.23.4'"));
  assert.ok(installer.includes("readonly RESTIC_VERSION='0.19.1'"));
  assert.ok(installer.includes("readonly RCLONE_VERSION='1.75.1'"));
  assert.equal(JSON.parse(read('package.json')).packageManager, 'pnpm@10.20.0');
  assert.equal(JSON.parse(read('agent/package.json')).version, '0.7.1');
});
