import { createHash } from "node:crypto";
import { constants } from "node:fs";
import type { Stats } from "node:fs";
import * as fs from "node:fs/promises";
import path from "node:path";
import { CommandStatusError, type CommandStatusCode } from "./commandStatus.js";
import {
  BackupCancelledError,
  BackupFilesystemError,
  ProgramExitError,
  ProgramTimeoutError,
  checkS3RepositoryAccess,
  obscureSensitiveSftpOptions,
  runProgram,
  validateRepositoryPath,
  validateS3PlainOptions,
  validateS3RepositoryPath,
  validateSftpPlainOptions,
  verifyRepository,
  writeTemporaryRcloneConfig,
} from "./backupFilesystem.js";
import { privateBinaryPath } from "./inventory.js";
import { assertRootOwnedPath } from "./lifecyclePolicy.js";
import {
  RestorePolicyError,
  approvedRestoreRoot,
  restoreRootLexicallyAllowed,
  type RestorePolicyContext,
  type RestorePolicyIO,
} from "./restorePolicy.js";
import {
  openSealedCommandSecrets,
  SealedSecretsError,
  type CommandSealContext,
} from "./sealedSecrets.js";
import type { AgentConfig } from "./types.js";

/**
 * RESTORE_FILESYSTEM payload version 1 (docs/AGENT_HOST_RESTORE.md in the server
 * repository). Restores one snapshot of this Agent's own managed repository into
 * a new folder inside a host-approved restore root. There is no in-place mode,
 * no overwrite and no deletion.
 */
export type RestoreFilesystemPayload = {
  version: 1;
  restoreId: string;
  planId: string;
  backupId: string;
  snapshotId: string;
  target: { root: string; name: string };
  selection: { includes: string[]; excludes: string[] };
  artifact?: { path: string; bytes: number; sha256: string };
  repository: { remoteName: "pluton"; path: string };
  rclone: { type: "sftp" | "s3"; options: Record<string, string> };
  /** Opened from `sealed`. Never logged. */
  repositoryPassword: string;
};

export type RestoreFilesystemResult = {
  restoreId: string;
  /** Not `snapshotId`: restore receipts never become backup parent candidates. */
  restoredSnapshotId: string;
  targetPath: string;
  totalFiles: number;
  filesRestored: number;
  totalBytes: number;
  bytesRestored: number;
  verified: true;
  artifactSha256?: string;
};

export type RestoreFilesystemStage =
  | "command-status-check"
  | "payload-validation"
  | "restore-policy"
  | "target-creation"
  | "tool-validation"
  | "sftp-password-obscure"
  | "temporary-storage-config"
  | "repository-check"
  | "snapshot-validation"
  | "space-check"
  | "restic-restore"
  | "artifact-verification"
  | "finalize"
  | "cleanup";

export type RestoreFilesystemFailureCode =
  | CommandStatusCode
  | "invalid-payload"
  | "restore-policy-invalid"
  | "restore-root-not-approved"
  | "restore-root-unsafe"
  | "restore-root-overlap"
  | "restore-target-exists"
  | "restore-target-failed"
  | "tool-unavailable"
  | "sftp-password-obscure-failed"
  | "temporary-config-failed"
  | "repository-check-failed"
  | "target-check-access-failed"
  | "target-check-auth-failed"
  | "target-check-transport-failed"
  | "restore-snapshot-mismatch"
  | "restore-selection-missing"
  | "restore-insufficient-space"
  | "restic-restore-failed"
  | "restore-verification-failed"
  | "restore-finalize-failed"
  | "cleanup-failed"
  | "cancelled"
  | "unexpected";

export class RestoreFilesystemError extends Error {
  constructor(
    readonly stage: RestoreFilesystemStage,
    readonly code: RestoreFilesystemFailureCode,
  ) {
    super(
      code === "cancelled"
        ? "Restore was cancelled."
        : `Agent host restore failed (${stage}/${code}).`,
    );
    this.name = "RestoreFilesystemError";
  }
}

const MAX_SELECTION_ENTRIES = 1024;
const MAX_SELECTION_CHARACTERS = 256 * 1024;
const MAX_ARTIFACT_BYTES = 100 * 1024 ** 3;
const RESTORE_TIMEOUT_MS = 72 * 60 * 60 * 1000;
const LISTING_TIMEOUT_MS = 6 * 60 * 60 * 1000;
const SNAPSHOT_TIMEOUT_MS = 5 * 60 * 1000;
const PROGRESS_INTERVAL_MS = 5_000;
const GIB = 1024 ** 3;
const STATE_RESERVE_BYTES = 512 * 1024 ** 2;
const INODE_RESERVE = 1_000;
export const PARTIAL_SUFFIX = ".partial";
const TARGET_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;
const ARTIFACT_PATH = /^\/pluton\/database\/[A-Za-z0-9_][A-Za-z0-9_.-]{0,95}\.sql$/;
const PAYLOAD_KEYS = new Set([
  "version",
  "restoreId",
  "planId",
  "backupId",
  "snapshotId",
  "target",
  "selection",
  "artifact",
  "repository",
  "rclone",
  "sealed",
]);

function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error(`${label} must be an object.`);
  return value as Record<string, unknown>;
}

function exactKeys(
  value: Record<string, unknown>,
  required: string[],
  optional: string[] = [],
): void {
  const keys = Object.keys(value);
  if (
    keys.some((key) => !required.includes(key) && !optional.includes(key)) ||
    required.some((key) => !Object.hasOwn(value, key))
  )
    throw new Error("Restore command contains unsupported fields.");
}

function identifier(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{1,160}$/.test(value))
    throw new Error(`${label} is invalid.`);
  return value;
}

/** Exact absolute snapshot path: Restic treats --include/--exclude as patterns. */
export function validateSnapshotSelectionPath(value: unknown): string {
  if (
    typeof value !== "string" ||
    !value.startsWith("/") ||
    value === "/" ||
    value.length > 4096 ||
    value.endsWith("/") ||
    value.includes("//") ||
    /[\x00-\x1f\x7f*?[\]\\]/.test(value) ||
    value
      .slice(1)
      .split("/")
      .some((part) => part === "" || part === "." || part === "..")
  )
    throw new Error("Restore selection path is invalid.");
  return value;
}

function selectionList(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > MAX_SELECTION_ENTRIES)
    throw new Error("Restore selection is invalid.");
  const paths = value.map(validateSnapshotSelectionPath);
  if (new Set(paths).size !== paths.length)
    throw new Error("Restore selection repeats a path.");
  return paths;
}

function within(parent: string, candidate: string): boolean {
  return candidate === parent || candidate.startsWith(`${parent}/`);
}

/**
 * Strict parser. Secrets exist only in `sealed` and are opened with the leased
 * command context; unknown fields, plain secrets and unsupported versions refuse.
 */
export function parseRestoreFilesystemPayload(
  value: Record<string, unknown>,
  commandSeal: CommandSealContext | undefined,
): RestoreFilesystemPayload {
  if (Object.keys(value).some((key) => !PAYLOAD_KEYS.has(key)))
    throw new Error("Restore command contains unsupported fields.");
  if (value.version !== 1)
    throw new Error("Restore command version is unsupported.");
  exactKeys(
    value,
    [
      "version",
      "restoreId",
      "planId",
      "backupId",
      "snapshotId",
      "target",
      "selection",
      "repository",
      "rclone",
      "sealed",
    ],
    ["artifact"],
  );
  if (typeof value.restoreId !== "string" || !/^[a-f0-9]{24}$/.test(value.restoreId))
    throw new Error("Restore ID is invalid.");
  if (typeof value.snapshotId !== "string" || !/^[a-f0-9]{64}$/.test(value.snapshotId))
    throw new Error("Snapshot ID must be a full Restic ID.");
  const target = record(value.target, "Restore target");
  exactKeys(target, ["root", "name"]);
  if (
    typeof target.root !== "string" ||
    typeof target.name !== "string" ||
    !TARGET_NAME.test(target.name) ||
    target.name.endsWith(PARTIAL_SUFFIX)
  )
    throw new Error("Restore target is invalid.");
  const selection = record(value.selection, "Restore selection");
  exactKeys(selection, ["includes", "excludes"]);
  const includes = selectionList(selection.includes);
  const excludes = selectionList(selection.excludes);
  // Restic restore cannot combine --include with --exclude; a selection is one or the other.
  if (includes.length && excludes.length)
    throw new Error("Restore selection cannot combine includes and excludes.");
  if (
    [...includes, ...excludes].reduce((sum, entry) => sum + entry.length, 0) >
    MAX_SELECTION_CHARACTERS
  )
    throw new Error("Restore selection is too large.");
  for (const entry of includes)
    if (includes.some((other) => other !== entry && within(other, entry)))
      throw new Error("Restore selection overlaps itself.");
  let artifact: RestoreFilesystemPayload["artifact"];
  if (value.artifact !== undefined) {
    const input = record(value.artifact, "Restore artifact");
    exactKeys(input, ["path", "bytes", "sha256"]);
    if (
      typeof input.path !== "string" ||
      !ARTIFACT_PATH.test(input.path) ||
      !Number.isSafeInteger(input.bytes) ||
      (input.bytes as number) < 1 ||
      (input.bytes as number) > MAX_ARTIFACT_BYTES ||
      typeof input.sha256 !== "string" ||
      !/^[a-f0-9]{64}$/.test(input.sha256) ||
      includes.length !== 1 ||
      includes[0] !== input.path ||
      excludes.length
    )
      throw new Error("Restore artifact is invalid.");
    artifact = {
      path: input.path,
      bytes: input.bytes as number,
      sha256: input.sha256,
    };
  }
  const repository = record(value.repository, "Repository configuration");
  exactKeys(repository, ["remoteName", "path"]);
  if (repository.remoteName !== "pluton")
    throw new Error("Repository configuration is invalid.");
  const rclone = record(value.rclone, "Rclone configuration");
  exactKeys(rclone, ["type", "options"]);
  if (rclone.type !== "sftp" && rclone.type !== "s3")
    throw new Error("Storage type is unsupported by this agent.");
  const type = rclone.type;
  const plain =
    type === "s3"
      ? validateS3PlainOptions(rclone.options)
      : validateSftpPlainOptions(rclone.options);
  if (!commandSeal)
    throw new Error("Sealed command secrets require the leased command context.");
  const secrets = openSealedCommandSecrets(value.sealed, commandSeal);
  if (secrets.lifecycle) throw new SealedSecretsError();
  const { pass, access_key_id, secret_access_key } = secrets.rclone;
  let options: Record<string, string>;
  if (type === "sftp") {
    if (!pass || access_key_id !== undefined || secret_access_key !== undefined)
      throw new SealedSecretsError();
    options = { ...plain, pass };
  } else {
    if (!access_key_id || !secret_access_key || pass !== undefined)
      throw new SealedSecretsError();
    options = { ...plain, access_key_id, secret_access_key };
  }
  if (secrets.repositoryPassword.length < 20 || secrets.repositoryPassword.length > 512)
    throw new Error("Repository password is invalid.");
  return {
    version: 1,
    restoreId: value.restoreId,
    planId: identifier(value.planId, "Plan ID"),
    backupId: identifier(value.backupId, "Backup ID"),
    snapshotId: value.snapshotId,
    target: { root: target.root, name: target.name },
    selection: { includes, excludes },
    ...(artifact ? { artifact } : {}),
    repository: {
      remoteName: "pluton",
      path:
        type === "s3"
          ? validateS3RepositoryPath(repository.path)
          : validateRepositoryPath(repository.path),
    },
    rclone: { type, options },
    repositoryPassword: secrets.repositoryPassword,
  };
}

function numeric(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0
    ? value
    : 0;
}

/** Whether a snapshot entry is part of the selection (exact path semantics). */
export function selectedBy(
  selection: RestoreFilesystemPayload["selection"],
  entry: string,
): boolean {
  if (selection.includes.length)
    return selection.includes.some((include) => within(include, entry));
  return !selection.excludes.some((exclude) => within(exclude, entry));
}

export type RestoreSizing = {
  bytes: number;
  entries: number;
  files: number;
  found: Set<string>;
  artifactSize?: number;
};

/** Consumes one `restic ls --json` line; snapshot lines and noise are ignored. */
export function addListingLine(
  sizing: RestoreSizing,
  selection: RestoreFilesystemPayload["selection"],
  line: string,
  artifactPath?: string,
): void {
  if (!line.trim()) return;
  let node: Record<string, unknown>;
  try {
    const parsed = JSON.parse(line) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return;
    node = parsed as Record<string, unknown>;
  } catch {
    return;
  }
  if (node.struct_type !== "node" && node.message_type !== "node") return;
  if (typeof node.path !== "string" || !node.path.startsWith("/")) return;
  const entry = node.path;
  if ([...selection.includes, ...selection.excludes].includes(entry))
    sizing.found.add(entry);
  if (!selectedBy(selection, entry)) return;
  sizing.entries += 1;
  if (node.type === "file") {
    sizing.files += 1;
    sizing.bytes += numeric(node.size);
    if (artifactPath && entry === artifactPath) sizing.artifactSize = numeric(node.size);
  }
}

/** Free space rule of section 6.4: bytes plus max(1 GiB, 5 %), inodes plus 1,000. */
export function spaceSufficient(
  required: { bytes: number; entries: number },
  available: { bytes: number; inodes?: number },
): boolean {
  const reserve = Math.max(GIB, Math.ceil(required.bytes * 0.05));
  if (!(available.bytes >= required.bytes + reserve)) return false;
  return (
    available.inodes === undefined ||
    available.inodes >= required.entries + INODE_RESERVE
  );
}

export function restoreProgressFromRestic(
  value: Record<string, unknown>,
): Record<string, unknown> | null {
  if (value.message_type !== "status") return null;
  return {
    phase: "running",
    restoreStage: "restoring",
    progress: {
      bytesProcessed: numeric(value.bytes_restored),
      filesProcessed: numeric(value.files_restored),
      totalBytesProcessed: numeric(value.total_bytes),
      totalFilesProcessed: numeric(value.total_files),
    },
  };
}

export function restoreProgressStage(stage: RestoreFilesystemStage): string {
  switch (stage) {
    case "repository-check":
    case "snapshot-validation":
      return "checking-repository";
    case "space-check":
      return "checking-space";
    case "restic-restore":
      return "restoring";
    case "artifact-verification":
      return "verifying";
    case "finalize":
    case "cleanup":
      return "finalizing";
    default:
      return "preparing-restore";
  }
}

const POLICY_FAILURES: Record<string, RestoreFilesystemFailureCode> = {
  "restore-root-not-approved": "restore-root-not-approved",
  "restore-root-overlap": "restore-root-overlap",
  "restore-root-denied": "restore-root-unsafe",
  "restore-root-invalid": "restore-root-unsafe",
  "restore-root-missing": "restore-root-unsafe",
  "restore-root-not-directory": "restore-root-unsafe",
  "restore-root-not-canonical": "restore-root-unsafe",
  "restore-root-owner": "restore-root-unsafe",
  "restore-root-mode": "restore-root-unsafe",
  "restore-root-ancestor-unsafe": "restore-root-unsafe",
  "restore-root-not-writable": "restore-root-unsafe",
  "restore-root-unavailable": "restore-root-unsafe",
};

function toRestoreError(
  error: unknown,
  stage: RestoreFilesystemStage,
): RestoreFilesystemError {
  if (error instanceof RestoreFilesystemError) return error;
  if (error instanceof BackupCancelledError)
    return new RestoreFilesystemError(stage, "cancelled");
  if (error instanceof CommandStatusError)
    return new RestoreFilesystemError("command-status-check", error.code);
  if (error instanceof RestorePolicyError)
    return new RestoreFilesystemError(
      "restore-policy",
      POLICY_FAILURES[error.code] || "restore-policy-invalid",
    );
  if (error instanceof BackupFilesystemError) {
    const allowed: RestoreFilesystemFailureCode[] = [
      "target-check-access-failed",
      "target-check-auth-failed",
      "target-check-transport-failed",
      "repository-check-failed",
      "sftp-password-obscure-failed",
      "cancelled",
    ];
    return new RestoreFilesystemError(
      stage,
      allowed.includes(error.code as RestoreFilesystemFailureCode)
        ? (error.code as RestoreFilesystemFailureCode)
        : "unexpected",
    );
  }
  if (error instanceof ProgramExitError && error.storageFailure)
    return new RestoreFilesystemError(stage, error.storageFailure);
  if (stage === "repository-check" && error instanceof ProgramTimeoutError)
    return new RestoreFilesystemError(stage, "target-check-transport-failed");
  const code: RestoreFilesystemFailureCode =
    stage === "payload-validation"
      ? "invalid-payload"
      : stage === "restore-policy"
        ? "restore-policy-invalid"
        : stage === "target-creation"
          ? "restore-target-failed"
          : stage === "tool-validation"
            ? "tool-unavailable"
            : stage === "sftp-password-obscure"
              ? "sftp-password-obscure-failed"
              : stage === "temporary-storage-config"
                ? "temporary-config-failed"
                : stage === "repository-check"
                  ? "repository-check-failed"
                  : stage === "snapshot-validation"
                    ? "restore-snapshot-mismatch"
                    : stage === "space-check"
                      ? "restore-selection-missing"
                      : stage === "restic-restore"
                        ? "restic-restore-failed"
                        : stage === "artifact-verification"
                          ? "restore-verification-failed"
                          : stage === "finalize"
                            ? "restore-finalize-failed"
                            : stage === "cleanup"
                              ? "cleanup-failed"
                              : "unexpected";
  return new RestoreFilesystemError(stage, code);
}

async function exists(io: RestorePolicyIO, filename: string): Promise<boolean> {
  try {
    await io.lstat(filename);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

function sameDirectory(a: Stats, b: Stats): boolean {
  return a.dev === b.dev && a.ino === b.ino && b.isDirectory() && !b.isSymbolicLink();
}

async function sha256File(
  filename: string,
  shouldCancel: () => Promise<boolean>,
): Promise<string> {
  const hash = createHash("sha256");
  const handle = await fs.open(filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stream = handle.createReadStream({
      highWaterMark: 1024 * 1024,
      autoClose: false,
    });
    let chunks = 0;
    for await (const chunk of stream) {
      hash.update(chunk as Buffer);
      if (++chunks % 1024 === 0 && (await shouldCancel())) {
        stream.destroy();
        throw new BackupCancelledError();
      }
    }
    return hash.digest("hex");
  } finally {
    await handle.close();
  }
}

export async function executeFilesystemRestore(input: {
  payload: Record<string, unknown>;
  commandSeal?: CommandSealContext;
  config: AgentConfig;
  agentId: string;
  /** Every source root the Agent knows (SourceAccessPolicy.report + static roots). */
  sourceRoots: string[];
  /** Strict status check at every stage boundary. */
  shouldCancel: () => Promise<boolean>;
  /** Periodic poll while Restic runs; may outlive a short outage within the lease. */
  shouldCancelDuringRestore?: () => Promise<boolean>;
  onProgress: (event: Record<string, unknown>) => void;
  onStage?: (stage: RestoreFilesystemStage) => void;
  /** Trusted test injection only; never derived from a command. */
  policy?: Pick<RestorePolicyContext, "io" | "uid" | "adminUid" | "platform">;
  /** Trusted test injection: skip the root-owned tool check of the private binaries. */
  trustToolDirectory?: boolean;
}): Promise<RestoreFilesystemResult> {
  let stage: RestoreFilesystemStage = "payload-validation";
  let temporary: { directory: string; configPath: string } | undefined;
  let operationError: unknown;
  let partialCreated: { path: string; stat: Stats } | undefined;
  let resticStarted = false;
  const setStage = (next: RestoreFilesystemStage) => {
    stage = next;
    try {
      input.onStage?.(next);
    } catch {
      /* Best-effort progress cannot fail native work. */
    }
  };
  const policyContext: RestorePolicyContext = {
    config: input.config,
    agentId: input.agentId,
    sourceRoots: input.sourceRoots,
    ...(input.policy || {}),
  };
  const io: RestorePolicyIO =
    input.policy?.io || (fs as unknown as RestorePolicyIO);
  const checkCancel = async () => {
    if (await input.shouldCancel()) throw new BackupCancelledError();
  };
  try {
    setStage("payload-validation");
    const payload = parseRestoreFilesystemPayload(input.payload, input.commandSeal);

    setStage("restore-policy");
    const lexical = restoreRootLexicallyAllowed(
      payload.target.root,
      input.config,
      input.sourceRoots,
    );
    if (lexical) throw new RestorePolicyError(lexical);
    const approved = await approvedRestoreRoot(policyContext, payload.target.root);
    const finalPath = path.posix.join(approved.root, payload.target.name);
    const partialPath = `${finalPath}${PARTIAL_SUFFIX}`;
    if (
      path.posix.dirname(finalPath) !== approved.root ||
      path.posix.basename(finalPath) !== payload.target.name
    )
      throw new RestoreFilesystemError("restore-policy", "restore-root-unsafe");
    setStage("target-creation");
    if ((await exists(io, finalPath)) || (await exists(io, partialPath)))
      throw new RestoreFilesystemError("target-creation", "restore-target-exists");
    await checkCancel();

    setStage("tool-validation");
    let restic = privateBinaryPath(input.config.binDir, "restic");
    let rclone = privateBinaryPath(input.config.binDir, "rclone");
    if (!input.trustToolDirectory) {
      restic = assertRootOwnedPath(await fs.realpath(restic));
      rclone = assertRootOwnedPath(await fs.realpath(rclone));
    }
    await Promise.all([
      fs.access(restic, constants.X_OK),
      fs.access(rclone, constants.X_OK),
    ]);
    const env: NodeJS.ProcessEnv = {
      PATH: `${path.dirname(restic)}:/usr/bin:/bin`,
      RESTIC_PASSWORD: payload.repositoryPassword,
      RESTIC_CACHE_DIR: path.join(input.config.dataDir, "restic-cache"),
    };
    const rcloneEnv: NodeJS.ProcessEnv = { PATH: env.PATH };
    let rcloneOptions = payload.rclone.options;
    if (payload.rclone.type === "sftp") {
      setStage("sftp-password-obscure");
      rcloneOptions = await obscureSensitiveSftpOptions(
        rclone,
        payload.rclone.options,
        rcloneEnv,
        input.shouldCancel,
      );
    }
    setStage("temporary-storage-config");
    if (payload.rclone.type === "s3" && input.config.storageCaFile) {
      const storageCa = assertRootOwnedPath(input.config.storageCaFile, false, true);
      env.SSL_CERT_FILE = storageCa;
      rcloneEnv.SSL_CERT_FILE = storageCa;
    }
    await fs.mkdir(input.config.dataDir, { recursive: true, mode: 0o700 });
    temporary = await writeTemporaryRcloneConfig(
      input.config.dataDir,
      rcloneOptions,
      payload.rclone.type,
    );
    env.RCLONE_CONFIG = temporary.configPath;
    rcloneEnv.RCLONE_CONFIG = temporary.configPath;
    const repository = `rclone:${payload.repository.remoteName}:${payload.repository.path}`;

    setStage("repository-check");
    if (payload.rclone.type === "s3")
      await checkS3RepositoryAccess(
        rclone,
        `${payload.repository.remoteName}:${payload.repository.path}`,
        rcloneEnv,
        input.shouldCancel,
        () => undefined,
      );
    await verifyRepository(restic, repository, env, input.shouldCancel, () => undefined);
    await checkCancel();

    setStage("snapshot-validation");
    const snapshots = await runProgram(
      restic,
      ["-r", repository, "snapshots", "--json", payload.snapshotId],
      {
        env,
        shouldCancel: input.shouldCancel,
        timeoutMs: SNAPSHOT_TIMEOUT_MS,
        maxOutputBytes: 1024 * 1024,
        allowFailure: true,
      },
    );
    let snapshot: Record<string, unknown> | undefined;
    try {
      const parsed = JSON.parse(snapshots.stdout) as unknown;
      if (
        snapshots.code === 0 &&
        !snapshots.outputTruncated &&
        Array.isArray(parsed) &&
        parsed.length === 1 &&
        parsed[0] &&
        typeof parsed[0] === "object"
      )
        snapshot = parsed[0] as Record<string, unknown>;
    } catch {
      snapshot = undefined;
    }
    const tags = Array.isArray(snapshot?.tags) ? (snapshot!.tags as unknown[]) : [];
    if (
      !snapshot ||
      snapshot.id !== payload.snapshotId ||
      !tags.includes(`pluton-plan-${payload.planId}`) ||
      !tags.includes(`pluton-backup-${payload.backupId}`)
    )
      throw new RestoreFilesystemError("snapshot-validation", "restore-snapshot-mismatch");
    await checkCancel();

    setStage("space-check");
    const sizing: RestoreSizing = { bytes: 0, entries: 0, files: 0, found: new Set() };
    await runProgram(
      restic,
      [
        "-r",
        repository,
        "ls",
        "--json",
        "--recursive",
        payload.snapshotId,
        ...payload.selection.includes,
      ],
      {
        env,
        shouldCancel: input.shouldCancel,
        timeoutMs: LISTING_TIMEOUT_MS,
        onStdoutLine: (line) =>
          addListingLine(sizing, payload.selection, line, payload.artifact?.path),
      },
    );
    if (
      [...payload.selection.includes, ...payload.selection.excludes].some(
        (entry) => !sizing.found.has(entry),
      ) ||
      sizing.entries === 0 ||
      (payload.artifact && sizing.artifactSize !== payload.artifact.bytes)
    )
      throw new RestoreFilesystemError("space-check", "restore-selection-missing");
    const rootSpace = await io.statfs(approved.root);
    const stateSpace = await io.statfs(input.config.dataDir);
    if (
      !spaceSufficient(
        { bytes: sizing.bytes, entries: sizing.entries },
        {
          bytes: Number(rootSpace.bavail) * Number(rootSpace.bsize),
          inodes: Number(rootSpace.files) > 0 ? Number(rootSpace.ffree) : undefined,
        },
      ) ||
      Number(stateSpace.bavail) * Number(stateSpace.bsize) < STATE_RESERVE_BYTES
    )
      throw new RestoreFilesystemError("space-check", "restore-insufficient-space");
    await checkCancel();

    setStage("target-creation");
    // Re-authorize after the long listing: the host administrator may have revoked it.
    await approvedRestoreRoot(policyContext, approved.root);
    try {
      await io.mkdir(partialPath, { mode: 0o700 });
    } catch (error) {
      throw new RestoreFilesystemError(
        "target-creation",
        (error as NodeJS.ErrnoException).code === "EEXIST"
          ? "restore-target-exists"
          : "restore-target-failed",
      );
    }
    const created = await io.lstat(partialPath);
    partialCreated = { path: partialPath, stat: created };
    if (
      !created.isDirectory() ||
      created.isSymbolicLink() ||
      created.uid !== (policyContext.uid ?? process.getuid?.()) ||
      (created.mode & 0o077) !== 0 ||
      (await io.realpath(partialPath)) !== partialPath ||
      (await fs.readdir(partialPath)).length !== 0
    )
      throw new RestoreFilesystemError("target-creation", "restore-target-failed");

    setStage("restic-restore");
    let summary: Record<string, unknown> | undefined;
    let lastProgress = 0;
    resticStarted = true;
    await runProgram(
      restic,
      [
        "-r",
        repository,
        "restore",
        payload.snapshotId,
        "--target",
        partialPath,
        "--overwrite",
        "never",
        "--verify",
        "--json",
        ...payload.selection.includes.flatMap((entry) => ["--include", entry]),
        ...payload.selection.excludes.flatMap((entry) => ["--exclude", entry]),
      ],
      {
        env,
        shouldCancel: input.shouldCancelDuringRestore ?? input.shouldCancel,
        timeoutMs: RESTORE_TIMEOUT_MS,
        classifyBackupStorageFailure: payload.rclone.type === "s3",
        onStdoutLine: (line) => {
          let value: Record<string, unknown>;
          try {
            const parsed = JSON.parse(line) as unknown;
            if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return;
            value = parsed as Record<string, unknown>;
          } catch {
            return;
          }
          if (value.message_type === "summary") {
            summary = value;
            return;
          }
          const progress = restoreProgressFromRestic(value);
          if (!progress || Date.now() - lastProgress < PROGRESS_INTERVAL_MS) return;
          lastProgress = Date.now();
          input.onProgress(progress);
        },
      },
    );
    const completed = summary as Record<string, unknown> | undefined;
    if (!completed)
      throw new RestoreFilesystemError("restic-restore", "restic-restore-failed");
    await checkCancel();

    let artifactSha256: string | undefined;
    if (payload.artifact) {
      setStage("artifact-verification");
      const restored = path.posix.join(partialPath, payload.artifact.path.slice(1));
      const info = await io.lstat(restored);
      if (!info.isFile() || info.isSymbolicLink() || info.size !== payload.artifact.bytes)
        throw new RestoreFilesystemError(
          "artifact-verification",
          "restore-verification-failed",
        );
      artifactSha256 = await sha256File(restored, input.shouldCancel);
      if (artifactSha256 !== payload.artifact.sha256)
        throw new RestoreFilesystemError(
          "artifact-verification",
          "restore-verification-failed",
        );
    }

    setStage("finalize");
    await approvedRestoreRoot(policyContext, approved.root);
    if (
      (await exists(io, finalPath)) ||
      !sameDirectory(created, await io.lstat(partialPath))
    )
      throw new RestoreFilesystemError("finalize", "restore-finalize-failed");
    await io.rename(partialPath, finalPath);
    partialCreated = undefined;
    const rootHandle = await io.open(
      approved.root,
      constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
    );
    try {
      await rootHandle.sync();
    } finally {
      await rootHandle.close();
    }
    return {
      restoreId: payload.restoreId,
      restoredSnapshotId: payload.snapshotId,
      targetPath: finalPath,
      totalFiles: numeric(completed.total_files),
      filesRestored: numeric(completed.files_restored),
      totalBytes: numeric(completed.total_bytes),
      bytesRestored: numeric(completed.bytes_restored),
      verified: true,
      ...(artifactSha256 ? { artifactSha256 } : {}),
    };
  } catch (error) {
    operationError = error;
    throw toRestoreError(error, stage);
  } finally {
    // A folder created moments ago that Restic never wrote to is provably empty:
    // remove only that (rmdir, never recursive). Anything Restic touched stays.
    if (partialCreated && !resticStarted)
      await fs.rmdir(partialCreated.path).catch(() => undefined);
    if (temporary) {
      try {
        setStage("cleanup");
        await fs.rm(temporary.directory, { recursive: true, force: true });
      } catch {
        // Never turn a verified restore, or the actionable failure, into a cleanup
        // failure. The start-up sweep removes a leftover temporary storage config.
        console.warn(
          `[pluton-agent] RESTORE_FILESYSTEM temporary storage config cleanup failed${operationError ? " after a failure" : ""}; it is removed at the next service start.`,
        );
      }
    }
  }
}
