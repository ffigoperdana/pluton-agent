import { execFileSync } from 'node:child_process';

// Public source plus native regressions exceeds Node's default 1 MiB capture.
// Keep an explicit ceiling; this does not bypass clean-source/revision checks.
export const MAX_SOURCE_ARCHIVE_BYTES = 16 * 1024 * 1024;
export function sourceArchive(root, sourceCommit, prefix) {
  return execFileSync('git', ['-C', root, 'archive', '--format=tar', `--prefix=${prefix}`, sourceCommit], {
    stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: MAX_SOURCE_ARCHIVE_BYTES,
  });
}
