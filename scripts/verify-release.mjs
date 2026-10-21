import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
export function verifyRelease(directory) {
  const root = path.resolve(directory),
    file = path.join(root, 'release-manifest.json');
  const manifest = JSON.parse(fs.readFileSync(file));
  if (
    manifest.format !== 1 ||
    !/^v0\.7\.\d+$/.test(manifest.version) ||
    !/^[a-f0-9]{40}$/.test(manifest.sourceCommit) ||
    manifest.platform !== 'linux-x64' ||
    manifest.artifacts.length !== 2
  )
    throw Error('Invalid release identity');
  const seen = new Set();
  for (const item of manifest.artifacts) {
    if (
      !/^[a-z0-9.-]+\.tar\.gz$/.test(item.file) ||
      seen.has(item.file) ||
      !/^[a-f0-9]{64}$/.test(item.sha256)
    )
      throw Error('Invalid artifact scope');
    seen.add(item.file);
    const target = path.join(root, item.file);
    if (!fs.lstatSync(target).isFile() || fs.lstatSync(target).isSymbolicLink())
      throw Error('Invalid artifact file');
    if (
      crypto
        .createHash('sha256')
        .update(fs.readFileSync(target))
        .digest('hex') !== item.sha256
    )
      throw Error('Artifact checksum mismatch');
  }
  console.log('PASS release identity and both immutable artifact checksums');
  return manifest;
}
if (process.argv[1] && path.resolve(process.argv[1]) === import.meta.filename)
  verifyRelease(process.argv[2] || 'release');
