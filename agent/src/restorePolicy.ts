import path from "node:path";
import { constants } from "node:fs";
import type { Stats, StatsFs } from "node:fs";
import * as fs from "node:fs/promises";
import { randomUUID } from "node:crypto";
import {
  assertNonoverlappingRoots,
  isNewSourceRootAllowed,
  sourcePathWithin,
  validateSourcePaths,
} from "./sourceAccessPolicy.js";
import type {
  AgentConfig,
  RestoreAccessReport,
  RestoreRootReport,
  SourceAccessReport,
} from "./types.js";

/**
 * Host-approved restore roots (docs/AGENT_HOST_RESTORE.md section 5 of the
 * server repository). A root-owned file names the only directories below which
 * a RESTORE_FILESYSTEM command may create a new folder. A command can never add,
 * widen or replace a root; the Agent account cannot write the file.
 */
export const RESTORE_POLICY_FILE = "/etc/pluton-agent/restore-roots.json";
export const MAX_RESTORE_ROOTS = 8;
const MAX_POLICY_BYTES = 64 * 1024;
/** Beyond the source-access denials: read-only under ProtectSystem=full, or shared. */
const RESTORE_DENIED_TREES = [
  "/usr",
  "/bin",
  "/sbin",
  "/lib",
  "/lib32",
  "/lib64",
  "/libx32",
  "/efi",
  "/run",
  "/tmp",
  "/var/tmp",
  "/var/run",
  "/var/lock",
  "/snap",
];

export type RestoreRootCode =
  | "restore-root-invalid"
  | "restore-root-denied"
  | "restore-root-overlap"
  | "restore-root-missing"
  | "restore-root-not-directory"
  | "restore-root-not-canonical"
  | "restore-root-owner"
  | "restore-root-mode"
  | "restore-root-ancestor-unsafe"
  | "restore-root-not-writable"
  | "restore-root-unavailable";

export type RestorePolicyCode =
  | "restore-policy-not-protected"
  | "restore-policy-invalid"
  | "restore-policy-agent-mismatch"
  | "restore-policy-unavailable"
  | "restore-source-policy-unavailable"
  | "restore-root-not-approved"
  | "restore-host-operator-required"
  | "restore-policy-linux-required"
  | RestoreRootCode;

export class RestorePolicyError extends Error {
  constructor(readonly code: RestorePolicyCode) {
    super(`Restore policy refused (${code}).`);
    this.name = "RestorePolicyError";
  }
}

type Handle = {
  readFile: (options: { encoding: "utf8" }) => Promise<string>;
  writeFile: (data: string, options: { encoding: "utf8" }) => Promise<void>;
  stat: () => Promise<Stats>;
  sync: () => Promise<void>;
  close: () => Promise<void>;
  chmod: (mode: number) => Promise<void>;
};

/** Injectable filesystem for deterministic ownership and race tests. */
export type RestorePolicyIO = {
  lstat: (filename: string) => Promise<Stats>;
  realpath: (filename: string) => Promise<string>;
  access: (filename: string, mode: number) => Promise<void>;
  statfs: (filename: string) => Promise<StatsFs>;
  open: (
    filename: string,
    flags: number | string,
    mode?: number,
  ) => Promise<Handle>;
  mkdir: (filename: string, options: { mode: number }) => Promise<unknown>;
  chmod: (filename: string, mode: number) => Promise<void>;
  rename: (oldPath: string, newPath: string) => Promise<void>;
  unlink: (filename: string) => Promise<void>;
};

export type RestorePolicyContext = {
  config: AgentConfig;
  agentId: string;
  /** The Agent service account. Restore roots must belong to it. */
  uid?: number;
  /** Owner required for the policy file and every root ancestor (root). */
  adminUid?: number;
  /** Every source root the Agent knows; a restore root never overlaps one. */
  sourceRoots?: string[];
  io?: RestorePolicyIO;
  platform?: string;
};

export type RestorePolicy = { version: 1; agentId: string; hostVersion: number; roots: string[] };

const defaultIO: RestorePolicyIO = fs as unknown as RestorePolicyIO;

function io(context: RestorePolicyContext): RestorePolicyIO {
  return context.io || defaultIO;
}

function adminUid(context: RestorePolicyContext): number {
  return context.adminUid ?? 0;
}

function agentUid(context: RestorePolicyContext): number {
  return context.uid ?? process.getuid?.() ?? -1;
}

function requireLinux(context: RestorePolicyContext): void {
  if ((context.platform || process.platform) !== "linux")
    throw new RestorePolicyError("restore-policy-linux-required");
}

export function restorePolicyFile(config: AgentConfig): string {
  return config.restorePolicyFile || RESTORE_POLICY_FILE;
}

/** Every source path the Agent reports, so a restore never lands in live data. */
export function knownSourceRoots(
  config: AgentConfig,
  report?: SourceAccessReport,
): string[] {
  return [
    ...new Set([
      ...config.allowedRoots,
      ...(report?.approvedRoots || []),
      ...(report?.effectiveRoots || []),
      ...(report?.delegatedRoots || []),
      ...(report?.rootStatuses || []).map((status) => status.path),
    ]),
  ].filter((entry) => typeof entry === "string" && entry.startsWith("/"));
}

/** Lexical rules shared by the policy reader, the CLI and execution. */
export function restoreRootLexicallyAllowed(
  root: string,
  config: AgentConfig,
  sourceRoots: string[] = [],
): RestoreRootCode | undefined {
  try {
    validateSourcePaths([root]);
  } catch {
    return "restore-root-invalid";
  }
  if (
    !isNewSourceRootAllowed(root) ||
    RESTORE_DENIED_TREES.some((tree) => sourcePathWithin(tree, root))
  )
    return "restore-root-denied";
  const state = path.posix.resolve(config.dataDir);
  for (const other of [state, ...sourceRoots])
    if (sourcePathWithin(other, root) || sourcePathWithin(root, other))
      return "restore-root-overlap";
  return undefined;
}

/** The authority file and every ancestor: administrator-owned and immutable to others. */
async function assertAdminOwned(
  context: RestorePolicyContext,
  filename: string,
  directory: boolean,
): Promise<Stats> {
  let current = filename;
  let leaf: Stats | undefined;
  for (;;) {
    const info = await io(context).lstat(current);
    if (
      info.isSymbolicLink() ||
      info.uid !== adminUid(context) ||
      (info.mode & 0o022) !== 0 ||
      (current === filename && !directory
        ? !info.isFile() || info.nlink !== 1
        : !info.isDirectory())
    )
      throw new RestorePolicyError("restore-policy-not-protected");
    leaf ||= info;
    if (current === path.posix.dirname(current)) break;
    current = path.posix.dirname(current);
  }
  return leaf;
}

function sameFile(a: Stats, b: Stats): boolean {
  return (
    a.dev === b.dev &&
    a.ino === b.ino &&
    a.size === b.size &&
    a.mtimeMs === b.mtimeMs &&
    a.uid === b.uid &&
    a.mode === b.mode
  );
}

/** Parses a policy body. Unknown keys, versions and bindings refuse. */
export function parseRestorePolicy(
  value: unknown,
  agentId: string,
): RestorePolicy {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).some(
      (key) => !["version", "agentId", "hostVersion", "roots"].includes(key),
    )
  )
    throw new RestorePolicyError("restore-policy-invalid");
  const body = value as Record<string, unknown>;
  if (
    body.version !== 1 ||
    !Number.isSafeInteger(body.hostVersion) ||
    (body.hostVersion as number) < 1 ||
    !Array.isArray(body.roots) ||
    body.roots.length > MAX_RESTORE_ROOTS
  )
    throw new RestorePolicyError("restore-policy-invalid");
  if (body.agentId !== agentId)
    throw new RestorePolicyError("restore-policy-agent-mismatch");
  let roots: string[];
  try {
    roots = validateSourcePaths(body.roots, true);
    assertNonoverlappingRoots(roots);
  } catch {
    throw new RestorePolicyError("restore-policy-invalid");
  }
  if (new Set(roots).size !== roots.length)
    throw new RestorePolicyError("restore-policy-invalid");
  return {
    version: 1,
    agentId,
    hostVersion: body.hostVersion as number,
    roots: [...roots].sort(),
  };
}

/** Reads the root-owned policy. A missing file approves nothing. */
export async function readRestorePolicy(
  context: RestorePolicyContext,
): Promise<RestorePolicy | undefined> {
  requireLinux(context);
  const filename = restorePolicyFile(context.config);
  let info: Stats;
  try {
    info = await io(context).lstat(filename);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw new RestorePolicyError("restore-policy-unavailable");
  }
  await assertAdminOwned(context, filename, false);
  if (info.size > MAX_POLICY_BYTES)
    throw new RestorePolicyError("restore-policy-invalid");
  const handle = await io(context).open(
    filename,
    constants.O_RDONLY | constants.O_NOFOLLOW,
  );
  let raw: string;
  try {
    if (!sameFile(info, await handle.stat()))
      throw new RestorePolicyError("restore-policy-not-protected");
    raw = await handle.readFile({ encoding: "utf8" });
    if (
      !sameFile(info, await handle.stat()) ||
      !sameFile(info, await io(context).lstat(filename))
    )
      throw new RestorePolicyError("restore-policy-not-protected");
  } finally {
    await handle.close();
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new RestorePolicyError("restore-policy-invalid");
  }
  return parseRestorePolicy(parsed, context.agentId);
}

function errorCode(error: unknown): string | undefined {
  return (error as NodeJS.ErrnoException | undefined)?.code;
}

/**
 * Full on-disk check of one root. Never creates, chowns or chmods anything.
 * `writable` is the only status the server may offer.
 */
export async function inspectRestoreRoot(
  context: RestorePolicyContext,
  root: string,
): Promise<RestoreRootReport> {
  const lexical = restoreRootLexicallyAllowed(
    root,
    context.config,
    context.sourceRoots,
  );
  if (lexical) return { path: root, status: "rejected", code: lexical };
  const fsio = io(context);
  let info: Stats;
  try {
    info = await fsio.lstat(root);
  } catch (error) {
    return {
      path: root,
      status: "unavailable",
      code:
        errorCode(error) === "ENOENT"
          ? "restore-root-missing"
          : "restore-root-unavailable",
    };
  }
  if (info.isSymbolicLink() || !info.isDirectory())
    return { path: root, status: "rejected", code: "restore-root-not-directory" };
  try {
    if ((await fsio.realpath(root)) !== root)
      return {
        path: root,
        status: "rejected",
        code: "restore-root-not-canonical",
      };
  } catch {
    return { path: root, status: "unavailable", code: "restore-root-unavailable" };
  }
  if (info.uid !== agentUid(context))
    return { path: root, status: "rejected", code: "restore-root-owner" };
  if ((info.mode & 0o077) !== 0)
    return { path: root, status: "rejected", code: "restore-root-mode" };
  let parent = path.posix.dirname(root);
  for (;;) {
    let ancestor: Stats;
    try {
      ancestor = await fsio.lstat(parent);
    } catch {
      return {
        path: root,
        status: "rejected",
        code: "restore-root-ancestor-unsafe",
      };
    }
    if (
      ancestor.isSymbolicLink() ||
      !ancestor.isDirectory() ||
      ancestor.uid !== adminUid(context) ||
      (ancestor.mode & 0o022) !== 0
    )
      return {
        path: root,
        status: "rejected",
        code: "restore-root-ancestor-unsafe",
      };
    if (parent === path.posix.dirname(parent)) break;
    parent = path.posix.dirname(parent);
  }
  try {
    await fsio.access(root, constants.W_OK | constants.X_OK);
  } catch {
    return { path: root, status: "unavailable", code: "restore-root-not-writable" };
  }
  try {
    const space = await fsio.statfs(root);
    const bytes = Number(space.bavail) * Number(space.bsize);
    return {
      path: root,
      status: "writable",
      ...(Number.isSafeInteger(bytes) && bytes >= 0
        ? { availableBytes: bytes }
        : {}),
      ...(Number(space.files) > 0 && Number.isSafeInteger(Number(space.ffree))
        ? { availableInodes: Number(space.ffree) }
        : {}),
    };
  } catch {
    return { path: root, status: "unavailable", code: "restore-root-unavailable" };
  }
}

/** Heartbeat report: never throws, never discloses file contents. */
export async function restoreAccessReport(
  context: RestorePolicyContext,
): Promise<RestoreAccessReport> {
  try {
    const policy = await readRestorePolicy(context);
    const roots: RestoreRootReport[] = [];
    for (const root of policy?.roots || [])
      roots.push(await inspectRestoreRoot(context, root));
    return { version: 1, roots };
  } catch (error) {
    return {
      version: 1,
      roots: [],
      policyError:
        error instanceof RestorePolicyError
          ? error.code
          : "restore-policy-unavailable",
    };
  }
}

/** Execution-time authorization of one signed root. Throws a closed code. */
export async function approvedRestoreRoot(
  context: RestorePolicyContext,
  root: string,
): Promise<{ root: string; availableBytes?: number; availableInodes?: number }> {
  const policy = await readRestorePolicy(context);
  if (!policy || !policy.roots.includes(root))
    throw new RestorePolicyError("restore-root-not-approved");
  const report = await inspectRestoreRoot(context, root);
  if (report.status !== "writable")
    throw new RestorePolicyError(
      (report.code as RestoreRootCode | undefined) || "restore-root-unavailable",
    );
  return {
    root,
    ...(report.availableBytes !== undefined
      ? { availableBytes: report.availableBytes }
      : {}),
    ...(report.availableInodes !== undefined
      ? { availableInodes: report.availableInodes }
      : {}),
  };
}

async function syncDirectory(
  context: RestorePolicyContext,
  directory: string,
): Promise<void> {
  const handle = await io(context).open(
    directory,
    constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
  );
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

/**
 * Local host-administrator operation (`pluton-agent restore-roots`). Requires
 * root. Validates each approved root on disk and writes the policy durably.
 * It never creates, chowns or chmods a restore root.
 */
export async function changeRestoreRoots(
  context: RestorePolicyContext & { operatorUid?: number },
  input: { action: "approve" | "revoke"; roots: string[] },
): Promise<{ roots: RestoreRootReport[]; hostVersion: number }> {
  requireLinux(context);
  if ((context.operatorUid ?? process.getuid?.()) !== adminUid(context))
    throw new RestorePolicyError("restore-host-operator-required");
  let candidates: string[];
  try {
    candidates = validateSourcePaths(input.roots);
  } catch {
    throw new RestorePolicyError("restore-root-invalid");
  }
  const current = (await readRestorePolicy(context)) || {
    version: 1 as const,
    agentId: context.agentId,
    hostVersion: 0,
    roots: [],
  };
  let roots: string[];
  if (input.action === "approve") {
    for (const root of candidates) {
      if (current.roots.includes(root))
        throw new RestorePolicyError("restore-policy-invalid");
      const report = await inspectRestoreRoot(context, root);
      if (report.status !== "writable")
        throw new RestorePolicyError(
          (report.code as RestoreRootCode | undefined) ||
            "restore-root-unavailable",
        );
    }
    roots = [...new Set([...current.roots, ...candidates])].sort();
    try {
      assertNonoverlappingRoots(roots);
    } catch {
      throw new RestorePolicyError("restore-root-overlap");
    }
    if (roots.length > MAX_RESTORE_ROOTS)
      throw new RestorePolicyError("restore-policy-invalid");
  } else {
    if (candidates.some((root) => !current.roots.includes(root)))
      throw new RestorePolicyError("restore-root-not-approved");
    roots = current.roots.filter((root) => !candidates.includes(root));
  }
  if (current.hostVersion >= Number.MAX_SAFE_INTEGER)
    throw new RestorePolicyError("restore-policy-invalid");
  const filename = restorePolicyFile(context.config);
  const directory = path.posix.dirname(filename);
  try {
    await assertAdminOwned(context, directory, true);
  } catch (error) {
    if (errorCode(error) !== "ENOENT") throw error;
    await assertAdminOwned(context, path.posix.dirname(directory), true);
    await io(context).mkdir(directory, { mode: 0o755 });
    await io(context).chmod(directory, 0o755);
    await assertAdminOwned(context, directory, true);
    await syncDirectory(context, path.posix.dirname(directory));
  }
  const next: RestorePolicy = {
    version: 1,
    agentId: context.agentId,
    hostVersion: current.hostVersion + 1,
    roots,
  };
  const temporary = `${filename}.${randomUUID()}.tmp`;
  let handle: Handle | undefined;
  try {
    handle = await io(context).open(
      temporary,
      constants.O_WRONLY |
        constants.O_CREAT |
        constants.O_EXCL |
        constants.O_NOFOLLOW,
      0o644,
    );
    await handle.chmod(0o644);
    await handle.writeFile(`${JSON.stringify(next, null, 2)}\n`, {
      encoding: "utf8",
    });
    await handle.sync();
    await handle.close();
    handle = undefined;
    await io(context).rename(temporary, filename);
    await syncDirectory(context, directory);
  } finally {
    if (handle) await handle.close().catch(() => undefined);
    await io(context).unlink(temporary).catch(() => undefined);
  }
  const written = await readRestorePolicy(context);
  if (!written || written.hostVersion !== next.hostVersion)
    throw new RestorePolicyError("restore-policy-unavailable");
  const reports: RestoreRootReport[] = [];
  for (const root of written.roots)
    reports.push(await inspectRestoreRoot(context, root));
  return { roots: reports, hostVersion: written.hostVersion };
}
