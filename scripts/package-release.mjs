import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { validate } from './validate-standalone.mjs';
import { verifyRelease } from './verify-release.mjs';
const root = path.resolve(import.meta.dirname, '..');
const git = (...args) =>
  execFileSync('git', ['-C', root, ...args], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
const sha = (data) => crypto.createHash('sha256').update(data).digest('hex');
validate();
if (process.platform !== 'linux')
  throw Error('Release tar metadata requires Linux GNU tar');
if (git('status', '--porcelain', '--untracked-files=normal').toString().trim())
  throw Error('Refusing release from dirty or uncommitted source');
const sourceCommit = git('rev-parse', '--verify', 'HEAD^{commit}')
  .toString()
  .trim();
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'))),
  version = 'v' + pkg.version;
if (!/^v0\.7\.\d+$/.test(version) || !/^[a-f0-9]{40}$/.test(sourceCommit))
  throw Error('Unsupported release identity');
const epoch = git('show', '-s', '--format=%ct', 'HEAD').toString().trim();
if (!/^\d+$/.test(epoch)) throw Error('Invalid source date');
const output = path.join(root, 'release');
fs.mkdirSync(output, { recursive: true });
const sourceName = `pluton-agent-${version}-source.tar.gz`,
  appName = `pluton-agent-${version}-linux-x64-app.tar.gz`;
fs.writeFileSync(
  path.join(output, sourceName),
  gzipSync(
    git(
      'archive',
      '--format=tar',
      `--prefix=pluton-agent-${version}/`,
      sourceCommit,
    ),
    { level: 9 },
  ),
);
const stage = fs.mkdtempSync(path.join(os.tmpdir(), 'pluton-agent-release-'));
try {
  const require = createRequire(path.join(root, 'agent/package.json'));
  if (require('typescript/package.json').version !== '5.9.3')
    throw Error('Unexpected compiler version');
  const compiled = path.join(stage, 'compiled');
  execFileSync(
    process.execPath,
    [
      require.resolve('typescript/bin/tsc'),
      '-p',
      path.join(root, 'agent/tsconfig.json'),
      '--outDir',
      compiled,
    ],
    { stdio: ['ignore', 'pipe', 'pipe'] },
  );
  if (
    git('status', '--porcelain', '--untracked-files=normal')
      .toString()
      .trim() ||
    git('rev-parse', 'HEAD').toString().trim() !== sourceCommit
  )
    throw Error('Source changed during packaging');
  fs.mkdirSync(path.join(stage, 'app/dist'), { recursive: true });
  const files = [];
  function copy(dir, relative = '') {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const name = path.posix.join(relative, entry.name),
        from = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) throw Error('Release build contains links');
      if (entry.isDirectory()) {
        fs.mkdirSync(path.join(stage, 'app/dist', name), { recursive: true });
        copy(from, name);
      } else if (
        entry.isFile() &&
        !/\.test\.(?:js|d\.ts|js\.map)$/.test(name)
      ) {
        fs.copyFileSync(from, path.join(stage, 'app/dist', name));
        files.push({
          file: 'app/dist/' + name,
          sha256: sha(fs.readFileSync(from)),
        });
      } else if (!entry.isFile())
        throw Error('Release build contains special files');
    }
  }
  copy(compiled);
  if (!files.some((f) => f.file === 'app/dist/index.js'))
    throw Error('Build missing');
  fs.copyFileSync(
    path.join(root, 'agent/package.json'),
    path.join(stage, 'app/package.json'),
  );
  fs.copyFileSync(path.join(root, 'LICENSE'), path.join(stage, 'LICENSE'));
  fs.copyFileSync(path.join(root, 'NOTICE'), path.join(stage, 'NOTICE'));
  fs.writeFileSync(
    path.join(stage, 'build-identity.json'),
    JSON.stringify(
      {
        version,
        sourceCommit,
        files: files.sort((a, b) => a.file.localeCompare(b.file, 'en')),
      },
      null,
      2,
    ) + '\n',
  );
  execFileSync(
    'tar',
    [
      '--sort=name',
      '--format=ustar',
      `--mtime=@${epoch}`,
      '--owner=0',
      '--group=0',
      '--numeric-owner',
      '--mode=u=rwX,go=rX',
      '-cf',
      path.join(stage, 'app.tar'),
      '-C',
      stage,
      'app',
      'LICENSE',
      'NOTICE',
      'build-identity.json',
    ],
    { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, LC_ALL: 'C' } },
  );
  fs.writeFileSync(
    path.join(output, appName),
    gzipSync(fs.readFileSync(path.join(stage, 'app.tar')), { level: 9 }),
  );
} finally {
  fs.rmSync(stage, { recursive: true, force: true });
}
const manifest = {
  format: 1,
  version,
  sourceCommit,
  platform: 'linux-x64',
  node: 'v22.23.4',
  pnpm: '10.20.0',
  contract: 'pluton-agent-0.7.0',
  activation:
    'reviewed-source-installer-only; app archive is not an activation bypass',
  artifacts: [sourceName, appName].map((file) => ({
    file,
    sha256: sha(fs.readFileSync(path.join(output, file))),
  })),
};
fs.writeFileSync(
  path.join(output, 'release-manifest.json'),
  JSON.stringify(manifest, null, 2) + '\n',
);
fs.writeFileSync(
  path.join(output, 'SHA256SUMS'),
  [
    ...manifest.artifacts,
    {
      file: 'release-manifest.json',
      sha256: sha(fs.readFileSync(path.join(output, 'release-manifest.json'))),
    },
  ]
    .map((x) => `${x.sha256}  ${x.file}\n`)
    .join(''),
);
verifyRelease(output);
