import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
const root = path.resolve(import.meta.dirname, '..');
export function validate() {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'))),
    app = JSON.parse(fs.readFileSync(path.join(root, 'agent/package.json')));
  if (
    pkg.packageManager !== 'pnpm@10.20.0' ||
    pkg.version !== app.version ||
    Object.keys(app.dependencies || {}).length
  )
    throw Error('Unsupported package/release dependency contract');
  if (
    fs.existsSync(path.join(root, 'backend')) ||
    fs.existsSync(path.join(root, 'frontend'))
  )
    throw Error('Unexpected server source');
  const types = JSON.parse(
    fs.readFileSync(path.join(root, 'agent/tsconfig.json')),
  ).compilerOptions.typeRoots;
  if (JSON.stringify(types) !== JSON.stringify(['./node_modules/@types']))
    throw Error('Nonlocal type roots');
  const workspace = fs
    .readFileSync(path.join(root, 'pnpm-workspace.yaml'), 'utf8')
    .replace(/^\s*#.*$/gm, '')
    .trim();
  if (
    !/^packages:\s*\n\s*-\s*['"]?agent['"]?$/.test(workspace) ||
    JSON.stringify(pkg.workspaces) !== JSON.stringify(['agent'])
  )
    throw Error('Nonlocal workspace');
  const audit = JSON.parse(
    fs.readFileSync(path.join(root, 'contracts/extraction-source.json')),
  );
  // Preserve the immutable extraction record. Independent runtime changes have
  // a separately versioned, explicit hash delta, not an extraction parity bypass.
  const delta = JSON.parse(fs.readFileSync(path.join(root, 'contracts/standalone-source-v1.json')));
  const digest = (source) => crypto.createHash('sha256').update(source.replace(/\r\n/g, '\n')).digest('hex');
  if (delta.format !== 1 || delta.agentVersion !== app.version ||
      delta.baseRevision !== '095088beeb3a10dc5fdda4f55db07fa4d17240be' ||
      delta.extractionManifestSha256 !== digest(fs.readFileSync(path.join(root, 'contracts/extraction-source.json'), 'utf8')))
    throw Error('Invalid independent source baseline');
  const expected = new Map(audit.agentSource.map(({file, sha256}) => [file, sha256]));
  if (fs.lstatSync(path.join(root, 'agent/src')).isSymbolicLink()) throw Error('Source directory link');
  const changed = new Set();
  for (const item of delta.changes) {
    if (!/^agent\/src\/[A-Za-z0-9]+(?:\.test)?\.ts$/.test(item.file) || changed.has(item.file) ||
        item.extractedSha256 !== (expected.get(item.file) ?? null) || !/^[a-f0-9]{64}$/.test(item.sha256) ||
        typeof item.reason !== 'string' || !item.reason.trim()) throw Error('Invalid explicit source change');
    changed.add(item.file); expected.set(item.file, item.sha256);
  }
  const actualFiles = fs.readdirSync(path.join(root, 'agent/src')).map((file) => 'agent/src/' + file).sort();
  if (JSON.stringify(actualFiles) !== JSON.stringify([...expected.keys()].sort())) throw Error('Unversioned Agent source file');
  for (const [file, sha256] of expected) {
    const source = fs.readFileSync(path.join(root, file), 'utf8');
    if (fs.lstatSync(path.join(root, file)).isSymbolicLink())
      throw Error('Source link');
    const actual = crypto
      .createHash('sha256')
      .update(source.replace(/\r\n/g, '\n'))
      .digest('hex');
    if (actual !== sha256)
      throw Error('Versioned standalone source parity changed: ' + file);
    for (const match of source.matchAll(
      /(?:from\s*|import\s*\()\s*["']([^"']+)["']/g,
    )) {
      if (!match[1].startsWith('./') && !match[1].startsWith('node:'))
        throw Error('External runtime import: ' + file);
    }
  }
  console.log(
    `PASS standalone layout and ${expected.size} versioned Agent source files (${changed.size} explicit independent changes); no server imports`,
  );
}
if (
  process.argv[1] &&
  path.resolve(process.argv[1]) ===
    path.join(root, 'scripts/validate-standalone.mjs')
)
  validate();
