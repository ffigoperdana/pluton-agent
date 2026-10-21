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
  for (const { file, sha256 } of audit.agentSource) {
    const source = fs.readFileSync(path.join(root, file), 'utf8');
    if (fs.lstatSync(path.join(root, file)).isSymbolicLink())
      throw Error('Source link');
    const actual = crypto
      .createHash('sha256')
      .update(source.replace(/\r\n/g, '\n'))
      .digest('hex');
    if (actual !== sha256)
      throw Error('Initial extraction parity changed: ' + file);
    for (const match of source.matchAll(
      /(?:from\s*|import\s*\()\s*["']([^"']+)["']/g,
    )) {
      if (!match[1].startsWith('./') && !match[1].startsWith('node:'))
        throw Error('External runtime import: ' + file);
    }
  }
  console.log(
    `PASS standalone layout and ${audit.agentSource.length} byte-identical Agent source files; no server imports`,
  );
}
if (
  process.argv[1] &&
  path.resolve(process.argv[1]) ===
    path.join(root, 'scripts/validate-standalone.mjs')
)
  validate();
