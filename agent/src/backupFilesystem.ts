import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import {
  access,
  chmod,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { constants } from "node:fs";
import path from "node:path";
import os from "node:os";
import { CommandStatusError, type CommandStatusCode } from "./commandStatus.js";
import {
  parseBackupExclusions,
  sourceResticExclusions,
  compileBackupExclusions,
} from "./backupExclusions.js";
import {
  addSourceProblem,
  newSourceDiagnostics,
  sourceProblemFromRestic,
  type SourceDiagnostics,
} from "./sourceDiagnostics.js";
import {
  compatibleResticParent,
  resticParentArgs,
  resticParentDiscoveryArgs,
  PARENT_LOOKUP_TIMEOUT_MS,
} from "./resticParent.js";
import {
  preflightSource,
  SourceAccessError,
  type SourceAccessCode,
} from "./filesystemPolicy.js";
import { privateBinaryPath } from "./inventory.js";
import { sourcePathContainsPrivateDirectory } from "./sourceAccessPolicy.js";
import type { AgentConfig } from "./types.js";
import { BackupLifecycleJob, BackupLifecycleError } from "./backupLifecycle.js";
import { runLifecycleProcess } from "./lifecycleProcess.js";
import {
  parseBackupLifecycle,
  assertRootOwnedPath,
  lifecycleDatabases,
  type BackupLifecycle,
  type DatabaseCheckpoint,
  type LifecycleCheckpoint,
  type LifecycleFailureCode,
  type LifecycleReport,
  type LifecycleStage,
} from "./lifecyclePolicy.js";
import {
  openSealedCommandSecrets,
  SealedSecretsError,
  type CommandSealContext,
  type SealedCommandSecrets,
} from "./sealedSecrets.js";

const MAX_OUTPUT_BYTES = 64 * 1024;
const PROGRESS_INTERVAL_MS = 5_000;

/**
 * Only the password-authenticated SFTP subset is supported for the first
 * remote data-plane path. In particular, never accept rclone options that
 * invoke an external SSH binary, a remote shell command, or an agent-local
 * credential file.
 */
const SFTP_OPTION_KEYS = new Set(["host", "port", "user", "pass"]);

/** Payload version 5 plain options (S3 design 10.2). Credentials only travel in `sealed`. */
const SFTP_PLAIN_OPTION_KEYS = new Set(["host", "port", "user"]);
const S3_PLAIN_OPTION_KEYS = new Set([
  "provider",
  "endpoint",
  "region",
  "location_constraint",
  "acl",
  "force_path_style",
  "use_accept_encoding_gzip",
  "no_check_bucket",
]);
const SEALED_ONLY_KEYS = new Set([
  "pass",
  "access_key_id",
  "secret_access_key",
  "repositoryPassword",
]);

export type BackupFilesystemPayload = {
  sourceDiagnosticsVersion?: 1;
  version: 1 | 2 | 3 | 4 | 5;
  lifecycle?: BackupLifecycle;
  backupId: string;
  planId: string;
  sourcePath: string;
  excludes: string[];
  repository: {
    remoteName: "pluton";
    /** SFTP directory, or `bucket/prefix` for S3 (version 5 only). */
    path: string;
    initialize: boolean;
  };
  rclone: {
    /** Versions 1 to 4 are SFTP-only; version 5 may name S3. */
    type: "sftp" | "s3";
    /** Plain options plus, in version 5, the opened sealed credentials. Never logged. */
    options: Record<string, string>;
  };
  /** Plain in versions 1 to 4, opened from `sealed` in version 5. Never logged. */
  repositoryPassword: string;
};

export type ResticSummary = {
  message_type: "summary";
  files_new: number;
  files_changed: number;
  files_unmodified: number;
  dirs_new: number;
  dirs_changed: number;
  dirs_unmodified: number;
  data_blobs: number;
  tree_blobs: number;
  data_added: number;
  data_added_packed: number;
  total_files_processed: number;
  total_bytes_processed: number;
  total_duration: number;
  snapshot_id: string;
};

export type BackupFilesystemResult = {
  snapshotId: string;
  sourcePaths?: string[];
  summary: ResticSummary;
  lifecycle?: LifecycleReport;
};

export class BackupCancelledError extends Error {
  constructor() {
    super("Backup was cancelled.");
  }
}

/**
 * Safe, bounded checkpoints for the remote data-plane operation.  These names
 * are intentionally closed rather than derived from provider output, paths, or
 * command arguments so they can be written to the local journal and returned
 * to the server without disclosing credentials.
 */
export type BackupFilesystemStage =
  | "post-dump-status-check"
  | "command-status-check"
  | "payload-validation"
  | "source-validation"
  | "state-validation"
  | "tool-validation"
  | "sftp-password-obscure"
  | "temporary-storage-config"
  | "repository-check"
  | "parent-discovery"
  | "parent-verification"
  | "repository-target-check"
  | "repository-initialization"
  | "restic-backup"
  | "cleanup"
  | LifecycleStage;

export type BackupFilesystemFailureCode =
  | CommandStatusCode
  | "invalid-payload"
  | "source-validation-failed"
  | SourceAccessCode
  | "state-overlap"
  | "state-validation-failed"
  | "tool-unavailable"
  | "sftp-password-obscure-failed"
  | "temporary-config-failed"
  | "repository-check-failed"
  | "repository-target-check-failed"
  | "repository-target-not-empty"
  | "target-check-access-failed"
  | "target-check-auth-failed"
  | "target-check-transport-failed"
  | "repository-initialization-failed"
  | "restic-backup-failed"
  | "restic-summary-missing"
  | "cleanup-failed"
  | "cancelled"
  | "unexpected"
  | LifecycleFailureCode;

export type BackupFilesystemStageEvent = {
  database?: DatabaseCheckpoint;
  diagnostic?: RepositoryDiagnostic;
  stage: BackupFilesystemStage;
  message:
    | "command accepted"
    | "stage started"
    | "source validated"
    | "temporary storage config created"
    | "repository check started"
    | "storage access check started"
    | "storage access verified"
    | "existing backup snapshot lookup started"
    | "initial repository verification started"
    | "repository verified"
    | "repository reverification started"
    | "real repository failure"
    | "parent candidate discovery started"
    | "parent metadata verification started"
    | "parent selected"
    | "no compatible parent"
    | "parent lookup timeout; checking repository before fallback"
    | "parent metadata invalid; checking repository before fallback"
    | "parent lookup failed; checking repository before fallback"
    | "parent lookup fallback; continuing without explicit parent"
    | "target-not-found"
    | "target-empty"
    | "repository initialization started"
    | "restic backup started"
    | "backup completed"
    | LifecycleCheckpoint;
};

const BACKUP_FAILURE_MESSAGES: Partial<
  Record<BackupFilesystemFailureCode, string>
> = {
  "invalid-payload": "The backup command payload is invalid.",
  "source-validation-failed": "The backup source could not be validated.",
  "source-parent-not-traversable":
    "A source parent directory is not traversable by the service account. Run local read-only preflight.",
  "source-root-not-readable":
    "The canonical source root is not readable/traversable by the service account.",
  "source-entry-inaccessible":
    "A source entry is inaccessible. Run the explicit local read-only source scan.",
  "source-missing": "The source or an expected source entry is missing.",
  "source-symlink-escape":
    "The source symlink escaped its allowed root or changed during validation.",
  "source-unsupported-type": "The source type is not supported.",
  "source-policy-violation":
    "The source violates the allowed-root path policy.",
  "state-overlap": "The backup source overlaps the agent state directory.",
  "state-validation-failed":
    "The agent state directory could not be validated.",
  "tool-unavailable": "The private backup tools are unavailable.",
  "sftp-password-obscure-failed":
    "The SFTP authentication configuration could not be prepared.",
  "temporary-config-failed":
    "The temporary storage configuration could not be prepared.",
  "repository-check-failed": "The Restic repository could not be checked.",
  "repository-target-check-failed":
    "The managed repository target could not be verified.",
  "repository-target-not-empty": "The managed repository target is not empty.",
  "target-check-access-failed":
    "Access to the managed repository target was denied.",
  "target-check-auth-failed":
    "Authentication for the managed repository target failed.",
  "target-check-transport-failed":
    "The connection to the managed repository target failed.",
  "repository-initialization-failed":
    "The Restic repository could not be initialized.",
  "restic-backup-failed": "Restic backup failed.",
  "restic-summary-missing": "Restic did not return a snapshot summary.",
  "cleanup-failed": "Temporary backup state could not be cleaned up.",
  cancelled: "Backup was cancelled.",
  unexpected: "Remote filesystem backup failed.",
};

export class BackupFilesystemError extends Error {
  constructor(
    readonly stage: BackupFilesystemStage,
    readonly code: BackupFilesystemFailureCode,
    readonly databaseId?: string,
    readonly engine?: "mysql" | "mariadb" | "postgresql",
    readonly sourceDiagnostics?: SourceDiagnostics,
  ) {
    super(BACKUP_FAILURE_MESSAGES[code] || "Remote backup lifecycle failed.");
    this.name = "BackupFilesystemError";
  }
}

export function toBackupFilesystemError(
  error: unknown,
  stage: BackupFilesystemStage,
): BackupFilesystemError {
  // Parent checkpoints are journal-only extensions; existing servers still
  // receive the established repository-check failure/cancellation vocabulary.
  if (stage === "parent-discovery" || stage === "parent-verification")
    stage = "repository-check";
  if (error instanceof BackupFilesystemError) return error;
  if (error instanceof CommandStatusError)
    return new BackupFilesystemError(
      stage === "post-dump-status-check" ? stage : "command-status-check",
      error.code,
    );
  if (error instanceof SourceAccessError)
    return new BackupFilesystemError(
      stage,
      error.code,
      undefined,
      undefined,
      error.sourceDiagnostics,
    );
  if (error instanceof BackupLifecycleError)
    return new BackupFilesystemError(
      error.stage,
      error.code,
      error.databaseId,
      error.engine,
    );
  if (error instanceof BackupCancelledError) {
    return new BackupFilesystemError(stage, "cancelled");
  }
  if (
    stage === "repository-check" &&
    error instanceof ProgramTimeoutError &&
    error.diagnostic
  ) {
    return new BackupFilesystemError(
      stage,
      error.diagnostic === "authentication-failed"
        ? "target-check-auth-failed"
        : error.diagnostic === "access-failed"
          ? "target-check-access-failed"
          : error.diagnostic === "transport-failed"
            ? "target-check-transport-failed"
            : "repository-check-failed",
    );
  }
  if (
    stage === "restic-backup" &&
    error instanceof ProgramExitError &&
    error.storageFailure
  )
    return new BackupFilesystemError(stage, error.storageFailure);
  const code: BackupFilesystemFailureCode =
    stage === "payload-validation"
      ? "invalid-payload"
      : stage === "source-validation"
        ? "source-validation-failed"
        : stage === "state-validation"
          ? error instanceof Error &&
            error.message ===
              "The backup source must not include the agent state directory."
            ? "state-overlap"
            : "state-validation-failed"
          : stage === "tool-validation"
            ? "tool-unavailable"
            : stage === "sftp-password-obscure"
              ? "sftp-password-obscure-failed"
              : stage === "temporary-storage-config"
                ? "temporary-config-failed"
                : stage === "repository-check"
                  ? "repository-check-failed"
                  : stage === "repository-target-check"
                    ? "repository-target-check-failed"
                    : stage === "repository-initialization"
                      ? "repository-initialization-failed"
                      : stage === "restic-backup"
                        ? "restic-backup-failed"
                        : stage === "cleanup"
                          ? "cleanup-failed"
                          : "unexpected";
  return new BackupFilesystemError(stage, code);
}

type ProcessResult = {
  code: number | null;
  stdout: string;
  targetFailureCode?: RepositoryTargetFailureCode;
  repositoryFailure?: RepositoryDiagnostic;
  outputTruncated?: boolean;
};

type RepositoryDiagnostic =
  | "authentication-failed"
  | "access-failed"
  | "transport-failed"
  | "repository-unavailable"
  | "invalid-repository"
  | "timeout"
  | "process-failed";
class ProgramTimeoutError extends Error {
  constructor(readonly diagnostic?: RepositoryDiagnostic) {
    super("Backup process timed out.");
  }
}

/** A classified S3 Restic failure; provider text never leaves runProgram. */
class ProgramExitError extends Error {
  constructor(readonly storageFailure?: RepositoryTargetFailureCode) {
    super("Backup process failed.");
  }
}

type RepositoryTargetFailureCode =
  | "target-check-access-failed"
  | "target-check-auth-failed"
  | "target-check-transport-failed";

type ProcessOptions = {
  maxOutputBytes?: number;
  cwd?: string;
  timeoutMs?: number;
  env: NodeJS.ProcessEnv;
  allowFailure?: boolean;
  classifyTargetFailure?: boolean;
  classifyRepositoryFailure?: boolean;
  /** S3 `restic backup` only: map storage-specific provider text to closed codes. */
  classifyBackupStorageFailure?: boolean;
  stdin?: string;
  shouldCancel: () => Promise<boolean>;
  onJsonLine?: (value: Record<string, unknown>) => Promise<void>;
  source?: string;
  sourceExcluded?: (relative: string) => boolean;
};

/** S3 SDK codes for a wrong or revoked key. Checked before 403 access, which they also carry. */
const S3_AUTHENTICATION_FAILURE = /SignatureDoesNotMatch|InvalidAccessKeyId/;
/** S3 refusals (AWS SDK v2 "StatusCode: 403", SDK v1 "status code: 403"). */
const S3_ACCESS_FAILURE = /\bAccessDenied\b|status ?code: 403\b/i;
/** Text only a storage transport produces: TCP/SSH, DNS, TLS, HTTP client timeouts and S3 5xx. */
const STORAGE_TRANSPORT_FAILURE =
  /dial tcp|connection refused|connection reset|connection closed|i\/o timeout|connection timed out|broken pipe|no route to host|network is unreachable|no such host|server misbehaving|x509: |tls: |TLS handshake timeout|Client\.Timeout exceeded|status ?code: 5\d\d\b|api error (?:InternalError|ServiceUnavailable|SlowDown)\b|(?:^|[\s:])(?:unexpected )?EOF(?:\s|$)/i;

function repositoryDiagnostic(
  code: number | null,
  diagnostics: string,
): RepositoryDiagnostic | undefined {
  if (
    code === 12 ||
    /wrong password|no key found|unable to authenticate|authentication failed|failed to authenticate|ssh: handshake failed.*authenticate/i.test(
      diagnostics,
    ) ||
    S3_AUTHENTICATION_FAILURE.test(diagnostics)
  )
    return "authentication-failed";
  if (
    /permission denied|access denied|operation not permitted/i.test(
      diagnostics,
    ) ||
    S3_ACCESS_FAILURE.test(diagnostics)
  )
    return "access-failed";
  if (classifyTargetFailure(diagnostics) === "target-check-transport-failed")
    return "transport-failed";
  if (code === 10) return "repository-unavailable";
  if (
    /ciphertext verification failed|invalid data returned|invalid repository|unsupported repository version|config.*(?:invalid|corrupt)|load.*snapshot.*(?:corrupt|invalid)/i.test(
      diagnostics,
    )
  )
    return "invalid-repository";
  if (code !== 0) return "process-failed";
  return undefined;
}

function asRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object.`);
  }
  return value as Record<string, unknown>;
}

function requiredString(value: unknown, label: string, max = 8_192): string {
  if (
    typeof value !== "string" ||
    !value ||
    value.length > max ||
    /[\x00-\x1f\x7f]/.test(value)
  ) {
    throw new Error(`${label} is invalid.`);
  }
  return value;
}

function validateId(value: unknown, label: string): string {
  const id = requiredString(value, label, 160);
  if (!/^[A-Za-z0-9_-]+$/.test(id)) throw new Error(`${label} is invalid.`);
  return id;
}

function validateRepositoryPath(value: unknown): string {
  const repositoryPath = requiredString(value, "Repository path");
  if (repositoryPath.split(/[\\/]+/).includes("..")) {
    throw new Error("Repository path contains traversal.");
  }
  return repositoryPath;
}

function validateExcludes(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > 100)
    throw new Error("Backup excludes are invalid.");
  return value.map((entry, index) => {
    const item = requiredString(entry, `Backup exclude ${index + 1}`, 4_096);
    if (item.split(/[\\/]+/).includes(".."))
      throw new Error("Backup excludes cannot contain traversal.");
    return item;
  });
}

function validateRcloneOptions(value: unknown): Record<string, string> {
  const input = asRecord(value, "SFTP configuration");
  const result: Record<string, string> = {};
  for (const [key, entry] of Object.entries(input)) {
    if (!SFTP_OPTION_KEYS.has(key))
      throw new Error("SFTP configuration contains an unsupported option.");
    const item = requiredString(entry, `SFTP option ${key}`, 16_384);
    result[key] = item;
  }
  if (!result.host || !result.user || !result.pass) {
    throw new Error("SFTP host, user, and password are required.");
  }
  return result;
}

function validateSftpPlainOptions(value: unknown): Record<string, string> {
  const input = asRecord(value, "SFTP configuration");
  const result: Record<string, string> = {};
  for (const [key, entry] of Object.entries(input)) {
    if (SEALED_ONLY_KEYS.has(key))
      throw new Error("SFTP credentials must be sealed.");
    if (!SFTP_PLAIN_OPTION_KEYS.has(key))
      throw new Error("SFTP configuration contains an unsupported option.");
    result[key] = requiredString(entry, `SFTP option ${key}`, 16_384);
  }
  if (!result.host || !result.user)
    throw new Error("SFTP host and user are required.");
  return result;
}

function validateS3PlainOptions(value: unknown): Record<string, string> {
  const input = asRecord(value, "S3 configuration");
  const result: Record<string, string> = {};
  for (const [key, entry] of Object.entries(input)) {
    if (SEALED_ONLY_KEYS.has(key))
      throw new Error("S3 credentials must be sealed.");
    if (!S3_PLAIN_OPTION_KEYS.has(key))
      throw new Error("S3 configuration contains an unsupported option.");
    result[key] = requiredString(entry, `S3 option ${key}`, 1_024);
  }
  let endpoint: URL | undefined;
  try {
    endpoint = new URL(result.endpoint || "");
  } catch {
    endpoint = undefined;
  }
  if (
    !endpoint ||
    endpoint.protocol !== "https:" ||
    endpoint.origin !== result.endpoint
  )
    throw new Error("S3 endpoint must be an HTTPS origin.");
  if (result.force_path_style !== "true")
    throw new Error("S3 path-style addressing is required.");
  if (result.use_accept_encoding_gzip !== "false")
    throw new Error("S3 transfer compression must be disabled.");
  if (
    result.no_check_bucket !== undefined &&
    result.no_check_bucket !== "true" &&
    result.no_check_bucket !== "false"
  )
    throw new Error("S3 bucket check option is invalid.");
  for (const key of ["provider", "region", "location_constraint", "acl"]) {
    if (
      result[key] !== undefined &&
      !/^[A-Za-z0-9._-]{1,128}$/.test(result[key])
    )
      throw new Error(`S3 option ${key} is invalid.`);
  }
  return result;
}

/** S3 repositories are a prefix inside a bucket; the bucket root is never a repository. */
function validateS3RepositoryPath(value: unknown): string {
  const repositoryPath = validateRepositoryPath(value);
  const segments = repositoryPath.split("/");
  if (
    repositoryPath.includes("\\") ||
    segments.length < 2 ||
    segments.some((segment) => !segment || segment === "." || segment === "..")
  )
    throw new Error("S3 repository path must be a prefix inside a bucket.");
  return repositoryPath;
}

/** Open version 5 secrets and merge them into the validated plain options. */
function openVersion5Secrets(
  type: "sftp" | "s3",
  optionsValue: unknown,
  sealedValue: unknown,
  commandSeal: CommandSealContext | undefined,
): {
  repositoryPassword: string;
  options: Record<string, string>;
  lifecycle: SealedCommandSecrets["lifecycle"];
} {
  const plain =
    type === "s3"
      ? validateS3PlainOptions(optionsValue)
      : validateSftpPlainOptions(optionsValue);
  if (!commandSeal)
    throw new Error(
      "Sealed command secrets require the leased command context.",
    );
  const secrets = openSealedCommandSecrets(sealedValue, commandSeal);
  const { pass, access_key_id, secret_access_key } = secrets.rclone;
  if (type === "sftp") {
    if (!pass || access_key_id !== undefined || secret_access_key !== undefined)
      throw new SealedSecretsError();
    return {
      repositoryPassword: secrets.repositoryPassword,
      options: { ...plain, pass },
      lifecycle: secrets.lifecycle,
    };
  }
  if (!access_key_id || !secret_access_key || pass !== undefined)
    throw new SealedSecretsError();
  return {
    repositoryPassword: secrets.repositoryPassword,
    options: { ...plain, access_key_id, secret_access_key },
    lifecycle: secrets.lifecycle,
  };
}

/**
 * Version 5 database passwords travel sealed (S3 design 10.3). Restore each one
 * into a copy of its plain lifecycle entry; the signed payload object is never
 * modified. A plain password, a database without a sealed password or a sealed
 * password without a matching database refuses the command.
 */
function withSealedDatabasePasswords(
  lifecycleValue: unknown,
  sealed: SealedCommandSecrets["lifecycle"],
): unknown {
  const unmatched = new Map(Object.entries(sealed?.databases ?? {}));
  let singleUnmatched = sealed?.database !== undefined;
  const restore = (entry: unknown, password: string | undefined) => {
    const database = asRecord(entry, "Database configuration");
    if (Object.hasOwn(database, "password"))
      throw new Error("Version 5 database passwords must be sealed.");
    if (password === undefined)
      throw new Error("A database has no sealed password.");
    return { ...database, password };
  };
  let restored: unknown = lifecycleValue;
  if (lifecycleValue !== undefined) {
    const lifecycle = asRecord(lifecycleValue, "Lifecycle configuration");
    const copy: Record<string, unknown> = { ...lifecycle };
    if (lifecycle.database !== undefined) {
      copy.database = restore(lifecycle.database, sealed?.database);
      singleUnmatched = false;
    }
    if (Array.isArray(lifecycle.databases))
      copy.databases = lifecycle.databases.map((entry) => {
        const databaseId = asRecord(entry, "Database configuration").databaseId;
        const password =
          typeof databaseId === "string"
            ? unmatched.get(databaseId)
            : undefined;
        if (typeof databaseId === "string") unmatched.delete(databaseId);
        return restore(entry, password);
      });
    restored = copy;
  }
  if (singleUnmatched || unmatched.size)
    throw new Error("A sealed database password has no matching database.");
  return restored;
}

/**
 * Parse the short, server-signed workflow envelope. Unknown fields are refused
 * so this cannot gradually turn into a generic remote execution protocol.
 * Version 5 (S3 design 10.2) adds S3 and carries every secret in `sealed`,
 * opened with the leased command context before any file is written.
 */
export function parseBackupFilesystemPayload(
  value: Record<string, unknown>,
  commandSeal?: CommandSealContext,
): BackupFilesystemPayload {
  const sealedVersion = value.version === 5;
  if (sealedVersion && Object.hasOwn(value, "repositoryPassword"))
    throw new Error("Version 5 secrets must be sealed.");
  const allowed = new Set([
    "version",
    "backupId",
    "planId",
    "sourcePath",
    "excludes",
    "repository",
    "rclone",
    sealedVersion ? "sealed" : "repositoryPassword",
    "sourceDiagnosticsVersion",
    ...([2, 3, 4, 5].includes(value.version as number) ? ["lifecycle"] : []),
  ]);
  if (Object.keys(value).some((key) => !allowed.has(key))) {
    throw new Error("Backup command contains unsupported fields.");
  }
  if (![1, 2, 3, 4, 5].includes(value.version as number))
    throw new Error("Backup command version is unsupported.");
  if (
    value.sourceDiagnosticsVersion !== undefined &&
    value.sourceDiagnosticsVersion !== 1
  )
    throw new Error("Source diagnostics version is unsupported.");
  const repository = asRecord(value.repository, "Repository configuration");
  const rclone = asRecord(value.rclone, "Rclone configuration");
  if (
    repository.remoteName !== "pluton" ||
    typeof repository.initialize !== "boolean"
  ) {
    throw new Error("Repository configuration is invalid.");
  }
  if (!sealedVersion && rclone.type !== "sftp")
    throw new Error("Only SFTP storage is supported by this agent.");
  if (sealedVersion && rclone.type !== "sftp" && rclone.type !== "s3")
    throw new Error("Storage type is unsupported by this agent.");
  const storageType = rclone.type as "sftp" | "s3";
  const opened = sealedVersion
    ? openVersion5Secrets(
        storageType,
        rclone.options,
        value.sealed,
        commandSeal,
      )
    : undefined;
  const password = requiredString(
    opened ? opened.repositoryPassword : value.repositoryPassword,
    "Repository password",
    512,
  );
  if (password.length < 20) throw new Error("Repository password is invalid.");
  const lifecycleInput = opened
    ? withSealedDatabasePasswords(value.lifecycle, opened.lifecycle)
    : value.lifecycle;
  const lifecycle =
    value.version === 1 ||
    ((value.version === 4 || value.version === 5) &&
      lifecycleInput === undefined)
      ? undefined
      : parseBackupLifecycle(lifecycleInput);
  if (
    lifecycle &&
    (value.version === 2 || value.version === 3) &&
    lifecycle.version !== (value.version === 3 ? 2 : 1)
  )
    throw new Error("Incompatible lifecycle envelope.");
  return {
    version: value.version as BackupFilesystemPayload["version"],
    ...(value.sourceDiagnosticsVersion === 1
      ? { sourceDiagnosticsVersion: 1 as const }
      : {}),
    ...(lifecycle ? { lifecycle } : {}),
    backupId: validateId(value.backupId, "Backup ID"),
    planId: validateId(value.planId, "Plan ID"),
    sourcePath: requiredString(value.sourcePath, "Source path", 4_096),
    excludes:
      value.version === 4 || value.version === 5
        ? parseBackupExclusions(value.excludes)
        : validateExcludes(value.excludes),
    repository: {
      remoteName: "pluton",
      path:
        storageType === "s3"
          ? validateS3RepositoryPath(repository.path)
          : validateRepositoryPath(repository.path),
      initialize: repository.initialize,
    },
    rclone: {
      type: storageType,
      options: opened ? opened.options : validateRcloneOptions(rclone.options),
    },
    repositoryPassword: password,
  };
}

/**
 * Version 5 replaces 1 to 4 for Agents that accept it, so it keeps the source
 * rules of the version the server would otherwise send. With exclusions that is
 * version 4: anchored exclusions, the pre-backup scan and excluded-path source
 * diagnostics. Without exclusions the source rules of versions 1 to 3 apply.
 */
function usesVersion4SourceRules(payload: BackupFilesystemPayload): boolean {
  return (
    payload.version === 4 ||
    (payload.version === 5 && payload.excludes.length > 0)
  );
}

/** Version 3, and version 5 with a version 2 lifecycle, bind the source and recover receipts. */
function bindsApplicationSource(payload: BackupFilesystemPayload): boolean {
  return (
    payload.version === 3 ||
    (payload.version === 5 && payload.lifecycle?.version === 2)
  );
}

function isWithin(parent: string, child: string): boolean {
  const relative = path.relative(parent, child);
  return (
    relative === "" ||
    (!relative.startsWith(`..${path.sep}`) &&
      relative !== ".." &&
      !path.isAbsolute(relative))
  );
}

async function assertSourceDoesNotOverlapState(
  source: string,
  dataDir: string,
): Promise<void> {
  await mkdir(dataDir, { recursive: true, mode: 0o700 });
  const state = await realpath(dataDir);
  if (isWithin(source, state) || isWithin(state, source)) {
    throw new Error(
      "The backup source must not include the agent state directory.",
    );
  }
}

function appendBounded(
  existing: string,
  chunk: string,
  limit = MAX_OUTPUT_BYTES,
): string {
  if (existing.length >= limit) return existing;
  return (existing + chunk).slice(0, limit);
}

/** Provider text is used only to categorize failures, never to permit init or log it. */
function classifyTargetFailure(
  diagnostics: string,
): RepositoryTargetFailureCode | undefined {
  if (
    /unable to authenticate|authentication failed|no supported methods remain|permission denied \((?:publickey|password|keyboard-interactive)/i.test(
      diagnostics,
    ) ||
    S3_AUTHENTICATION_FAILURE.test(diagnostics)
  ) {
    return "target-check-auth-failed";
  }
  if (
    /permission denied|access denied|SSH_FX_PERMISSION_DENIED|operation not permitted/i.test(
      diagnostics,
    ) ||
    S3_ACCESS_FAILURE.test(diagnostics)
  ) {
    return "target-check-access-failed";
  }
  if (STORAGE_TRANSPORT_FAILURE.test(diagnostics)) {
    return "target-check-transport-failed";
  }
  return undefined;
}

/** Restic backup stderr also carries source errors, so only storage-specific provider text is classified. */
function classifyBackupStorageFailure(
  diagnostics: string,
): RepositoryTargetFailureCode | undefined {
  if (S3_AUTHENTICATION_FAILURE.test(diagnostics))
    return "target-check-auth-failed";
  if (S3_ACCESS_FAILURE.test(diagnostics)) return "target-check-access-failed";
  if (STORAGE_TRANSPORT_FAILURE.test(diagnostics))
    return "target-check-transport-failed";
  return undefined;
}

function terminateProcessTree(
  child: ChildProcessWithoutNullStreams,
): ReturnType<typeof setTimeout> | undefined {
  // On Linux, descendants can still hold stdio open after the leader exits.
  if (process.platform === "win32" && (child.exitCode !== null || child.killed))
    return;
  try {
    if (process.platform === "win32" && child.pid) {
      const killer = spawn("taskkill", ["/PID", String(child.pid), "/T"], {
        shell: false,
        windowsHide: true,
        stdio: "ignore",
      });
      killer.once("error", () => {
        try {
          child.kill("SIGTERM");
        } catch {
          // The process has already stopped.
        }
      });
      killer.unref();
    } else if (child.pid) process.kill(-child.pid, "SIGTERM");
    else child.kill("SIGTERM");
  } catch {
    child.kill("SIGTERM");
  }
  const forceKill = setTimeout(() => {
    try {
      if (process.platform === "win32" && child.pid) {
        const killer = spawn(
          "taskkill",
          ["/PID", String(child.pid), "/T", "/F"],
          {
            shell: false,
            windowsHide: true,
            stdio: "ignore",
          },
        );
        killer.once("error", () => {
          try {
            child.kill("SIGKILL");
          } catch {
            // The process has already stopped.
          }
        });
        killer.unref();
      } else if (child.pid) process.kill(-child.pid, "SIGKILL");
      else child.kill("SIGKILL");
    } catch {
      // The process has already stopped.
    }
  }, 5_000);
  forceKill.unref();
  return forceKill;
}

async function runProgram(
  binary: string,
  args: string[],
  options: ProcessOptions,
): Promise<ProcessResult> {
  await access(binary, constants.X_OK);
  return new Promise<ProcessResult>((resolve, reject) => {
    const child = spawn(binary, args, {
      shell: false,
      detached: process.platform !== "win32",
      windowsHide: true,
      env: options.env,
      stdio: ["pipe", "pipe", "pipe"],
      cwd: options.cwd,
    });
    let stdout = "";
    let diagnostics = "";
    let stdoutBuffer = "";
    let stderrBuffer = "";
    let sourceFailure: SourceAccessCode | undefined;
    const sourceDiagnostics = newSourceDiagnostics("restic");
    const consumeSourceLine = (line: string) => {
      if (!options.source) return;
      const problem = sourceProblemFromRestic(
        line,
        options.source,
        options.sourceExcluded,
      );
      if (!problem) return;
      addSourceProblem(sourceDiagnostics, problem);
      if (!sourceFailure || problem.errno !== "ENOENT")
        sourceFailure =
          problem.errno === "ENOENT"
            ? "source-missing"
            : "source-entry-inaccessible";
    };
    let cancelled = false;
    let statusFailure: CommandStatusError | undefined;
    let checking = false;
    let eventChain = Promise.resolve();
    let settled = false;
    let timedOut = false;
    let outputBytes = 0;
    let forceKill: ReturnType<typeof setTimeout> | undefined;
    const deadline = options.timeoutMs
      ? setTimeout(() => {
          timedOut = true;
          forceKill ||= terminateProcessTree(child);
        }, options.timeoutMs)
      : undefined;

    const cancellationTimer = setInterval(() => {
      if (checking || settled) return;
      checking = true;
      void options
        .shouldCancel()
        .then((shouldCancel) => {
          if (!shouldCancel || cancelled || settled) return;
          cancelled = true;
          forceKill ||= terminateProcessTree(child);
        })
        .catch((error) => {
          if (error instanceof CommandStatusError && !settled) {
            statusFailure = error;
            forceKill ||= terminateProcessTree(child);
          }
        })
        .finally(() => {
          checking = false;
        });
    }, 10_000);
    cancellationTimer.unref();

    const consumeLine = (line: string) => {
      consumeSourceLine(line);
      if (!options.onJsonLine || !line.trim()) return;
      try {
        const parsed = JSON.parse(line) as unknown;
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
          return;
        eventChain = eventChain.then(() =>
          options.onJsonLine!(parsed as Record<string, unknown>),
        );
      } catch {
        // Restic may emit non-JSON diagnostics. They are never forwarded to the control plane.
      }
    };

    child.stdout.on("data", (chunk) => {
      const text = String(chunk);
      outputBytes += Buffer.byteLength(text);
      stdout = appendBounded(stdout, text, options.maxOutputBytes);
      stdoutBuffer = appendBounded(stdoutBuffer, text);
      for (;;) {
        const newline = stdoutBuffer.indexOf("\n");
        if (newline < 0) break;
        const line = stdoutBuffer.slice(0, newline);
        stdoutBuffer = stdoutBuffer.slice(newline + 1);
        consumeLine(line);
      }
    });
    child.stderr.on("data", (chunk) => {
      // Target/repository probes use only a bounded in-memory classifier.
      // Raw provider text is never returned, logged, or forwarded to the server.
      if (
        options.classifyTargetFailure ||
        options.classifyRepositoryFailure ||
        options.classifyBackupStorageFailure
      ) {
        diagnostics = appendBounded(diagnostics, String(chunk));
      }
      if (options.source) {
        stderrBuffer = appendBounded(stderrBuffer, String(chunk));
        const lines = stderrBuffer.split("\n");
        stderrBuffer = lines.pop() || "";
        for (const line of lines) consumeSourceLine(line);
      }
    });
    child.stdin.end(options.stdin || "");
    child.once("error", (error) => {
      settled = true;
      clearInterval(cancellationTimer);
      if (deadline) clearTimeout(deadline);
      if (forceKill) clearTimeout(forceKill);
      reject(error);
    });
    child.once("close", (code: number | null) => {
      settled = true;
      clearInterval(cancellationTimer);
      if (deadline) clearTimeout(deadline);
      if (forceKill) clearTimeout(forceKill);
      consumeLine(stdoutBuffer);
      void eventChain.then(
        () => {
          if (statusFailure) return reject(statusFailure);
          if (cancelled) return reject(new BackupCancelledError());
          if (timedOut) {
            if (options.classifyBackupStorageFailure)
              return reject(
                new ProgramExitError(classifyBackupStorageFailure(diagnostics)),
              );
            const reason = options.classifyRepositoryFailure
              ? repositoryDiagnostic(code, diagnostics)
              : undefined;
            return reject(
              new ProgramTimeoutError(
                reason === "process-failed" ? undefined : reason,
              ),
            );
          }
          consumeSourceLine(stderrBuffer);
          if ((code !== 0 || sourceFailure) && !options.allowFailure) {
            if (sourceFailure)
              return reject(
                new SourceAccessError(
                  sourceFailure,
                  undefined,
                  undefined,
                  undefined,
                  sourceDiagnostics,
                ),
              );
            return reject(
              options.classifyBackupStorageFailure
                ? new ProgramExitError(
                    classifyBackupStorageFailure(diagnostics),
                  )
                : new Error(
                    `Backup process exited with status ${code ?? "unknown"}.`,
                  ),
            );
          }
          resolve({
            code,
            stdout,
            outputTruncated:
              outputBytes > (options.maxOutputBytes ?? MAX_OUTPUT_BYTES),
            ...(options.classifyRepositoryFailure
              ? { repositoryFailure: repositoryDiagnostic(code, diagnostics) }
              : {}),
            ...(options.classifyTargetFailure
              ? { targetFailureCode: classifyTargetFailure(diagnostics) }
              : {}),
          });
        },
        (error) => reject(error),
      );
    });
  });
}

/** Authenticate/decrypt the exact repository config, without snapshot enumeration or locks. */
async function verifyRepository(
  restic: string,
  repository: string,
  env: NodeJS.ProcessEnv,
  shouldCancel: () => Promise<boolean>,
  diagnostic: (reason: RepositoryDiagnostic) => void,
): Promise<void> {
  let reason: RepositoryDiagnostic | undefined;
  try {
    const result = await runProgram(
      restic,
      ["-r", repository, "--no-lock", "cat", "config"],
      {
        env,
        shouldCancel,
        timeoutMs: 30_000,
        allowFailure: true,
        classifyRepositoryFailure: true,
      },
    );
    reason = result.repositoryFailure;
    if (!reason) {
      try {
        const config = JSON.parse(result.stdout);
        if (
          result.outputTruncated ||
          !config ||
          ![1, 2].includes(config.version) ||
          !/^[a-f0-9]{64}$/.test(config.id)
        )
          reason = "invalid-repository";
      } catch {
        reason = "invalid-repository";
      }
    }
  } catch (error) {
    if (error instanceof BackupCancelledError) throw error;
    reason =
      error instanceof ProgramTimeoutError
        ? error.diagnostic || "timeout"
        : "process-failed";
  }
  if (reason) {
    diagnostic(reason);
    throw new BackupFilesystemError(
      "repository-check",
      reason === "authentication-failed"
        ? "target-check-auth-failed"
        : reason === "access-failed"
          ? "target-check-access-failed"
          : reason === "transport-failed"
            ? "target-check-transport-failed"
            : "repository-check-failed",
    );
  }
}

/**
 * S3 credentials and reachability, checked by Rclone directly before Restic:
 * Restic's Rclone bridge (`rclone serve restic`) turns provider errors into
 * plain HTTP statuses. A missing prefix lists as empty with exit 0; any other
 * exit, including 3 (missing bucket), fails without a retry loop.
 */
async function checkS3RepositoryAccess(
  rclone: string,
  target: string,
  env: NodeJS.ProcessEnv,
  shouldCancel: () => Promise<boolean>,
  diagnostic: (reason: RepositoryDiagnostic) => void,
): Promise<void> {
  let reason: RepositoryDiagnostic | undefined;
  try {
    const result = await runProgram(rclone, ["lsf", target], {
      env,
      shouldCancel,
      timeoutMs: 30_000,
      allowFailure: true,
      classifyRepositoryFailure: true,
    });
    if (result.code === 0) return;
    reason = result.repositoryFailure;
  } catch (error) {
    if (
      error instanceof BackupCancelledError ||
      error instanceof CommandStatusError
    )
      throw error;
    reason =
      error instanceof ProgramTimeoutError
        ? error.diagnostic || "timeout"
        : "process-failed";
  }
  diagnostic(reason || "process-failed");
  throw new BackupFilesystemError(
    "repository-check",
    reason === "authentication-failed"
      ? "target-check-auth-failed"
      : reason === "access-failed"
        ? "target-check-access-failed"
        : reason === "transport-failed" || reason === "timeout"
          ? "target-check-transport-failed"
          : "repository-check-failed",
  );
}

function rcloneConfigValue(value: string): string {
  if (/[\r\n\x00]/.test(value))
    throw new Error("SFTP configuration contains an unsafe value.");
  return value;
}

export async function writeTemporaryRcloneConfig(
  dataDir: string,
  options: Record<string, string>,
  type: "sftp" | "s3" = "sftp",
): Promise<{ directory: string; configPath: string }> {
  const directory = await mkdtemp(path.join(dataDir, "rclone-"));
  await chmod(directory, 0o700);
  const configPath = path.join(directory, "rclone.conf");
  // S3 keys stay plain in this 0600 file (rclone obscure is SFTP-only) and an S3
  // remote never falls back to ambient AWS credentials of the Agent host.
  const lines = [
    "[pluton]",
    `type = ${type}`,
    ...(type === "s3" ? ["env_auth = false"] : []),
  ];
  for (const key of Object.keys(options).sort()) {
    lines.push(`${key} = ${rcloneConfigValue(options[key])}`);
  }
  await writeFile(configPath, `${lines.join("\n")}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  await chmod(configPath, 0o600);
  return { directory, configPath };
}

async function obscureSensitiveSftpOptions(
  rclone: string,
  options: Record<string, string>,
  env: NodeJS.ProcessEnv,
  shouldCancel: () => Promise<boolean>,
): Promise<Record<string, string>> {
  const obscured = { ...options };
  for (const key of ["pass", "key_file_pass"]) {
    if (!obscured[key]) continue;
    const result = await runProgram(rclone, ["obscure", "-"], {
      env,
      stdin: `${obscured[key]}\n`,
      shouldCancel,
    });
    const value = result.stdout.trim();
    if (!value || /[\r\n\x00]/.test(value)) {
      throw new BackupFilesystemError(
        "sftp-password-obscure",
        "sftp-password-obscure-failed",
      );
    }
    obscured[key] = value;
  }
  return obscured;
}

function numeric(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0
    ? value
    : 0;
}

/** Only classify JSON source errors, not arbitrary storage/provider text. Raw output stays local in memory. */
export function sourceFailureFromRestic(
  line: string,
  source: string,
): SourceAccessCode | undefined {
  const problem = sourceProblemFromRestic(line, source);
  return problem
    ? problem.errno === "ENOENT"
      ? "source-missing"
      : "source-entry-inaccessible"
    : undefined;
}

function summaryFromRestic(
  value: Record<string, unknown>,
): ResticSummary | null {
  if (
    value.message_type !== "summary" ||
    typeof value.snapshot_id !== "string" ||
    !/^[A-Fa-f0-9]{8,128}$/.test(value.snapshot_id)
  ) {
    return null;
  }
  return {
    message_type: "summary",
    files_new: numeric(value.files_new),
    files_changed: numeric(value.files_changed),
    files_unmodified: numeric(value.files_unmodified),
    dirs_new: numeric(value.dirs_new),
    dirs_changed: numeric(value.dirs_changed),
    dirs_unmodified: numeric(value.dirs_unmodified),
    data_blobs: numeric(value.data_blobs),
    tree_blobs: numeric(value.tree_blobs),
    data_added: numeric(value.data_added),
    data_added_packed: numeric(value.data_added_packed),
    total_files_processed: numeric(value.total_files_processed),
    total_bytes_processed: numeric(value.total_bytes_processed),
    total_duration: numeric(value.total_duration),
    snapshot_id: value.snapshot_id.slice(0, 128),
  };
}

export function progressFromRestic(
  value: Record<string, unknown>,
): Record<string, unknown> | null {
  if (value.message_type !== "status") return null;
  return {
    phase: "running",
    backupStage: "backing-up",
    progress: {
      bytesProcessed: numeric(value.bytes_done),
      filesProcessed: numeric(value.files_done),
      totalBytesProcessed: numeric(value.total_bytes),
      totalFilesProcessed: numeric(value.total_files),
    },
  };
}

async function ensureManagedRepository(
  payload: BackupFilesystemPayload,
  restic: string,
  rclone: string,
  repository: string,
  resticEnv: NodeJS.ProcessEnv,
  rcloneEnv: NodeJS.ProcessEnv,
  shouldCancel: () => Promise<boolean>,
  onRepositoryInitializationStarted?: () => void,
  onTargetChecked?: (result: "target-not-found" | "target-empty") => void,
): Promise<void> {
  if (!payload.repository.initialize) return;
  const snapshots = await runProgram(
    restic,
    ["-r", repository, "snapshots", "--json"],
    {
      env: resticEnv,
      allowFailure: true,
      shouldCancel,
    },
  );
  if (snapshots.code === 0) return;

  const listing = await runProgram(
    rclone,
    ["lsf", `${payload.repository.remoteName}:${payload.repository.path}`],
    {
      env: rcloneEnv,
      allowFailure: true,
      classifyTargetFailure: true,
      shouldCancel,
    },
  );
  // Rclone reserves exit code 3 for fs.ErrorDirNotFound. Do not infer absence
  // from free-form "not found" text (e.g. a missing config or SSH key), exit
  // code 4 (file not found), or any authentication/access/transport failure.
  // S3 has no directories: a missing prefix lists as empty with exit 0, and
  // exit 3 means the bucket itself is missing, which never permits init.
  const missingTarget =
    payload.rclone.type === "sftp" &&
    listing.code === 3 &&
    !listing.targetFailureCode;
  if (listing.code !== 0 && !missingTarget) {
    throw new BackupFilesystemError(
      "repository-target-check",
      listing.targetFailureCode || "repository-target-check-failed",
    );
  }
  // Even whitespace-only filenames or partial output must refuse initialization.
  if (listing.stdout.length > 0) {
    throw new BackupFilesystemError(
      "repository-target-check",
      "repository-target-not-empty",
    );
  }
  onTargetChecked?.(missingTarget ? "target-not-found" : "target-empty");

  try {
    onRepositoryInitializationStarted?.();
    await runProgram(restic, ["-r", repository, "init"], {
      env: resticEnv,
      shouldCancel,
    });
  } catch (error) {
    // A lost completion response can cause an idempotent retry after `init`
    // succeeded. Accept it only when this exact password can open the repo.
    const retry = await runProgram(
      restic,
      ["-r", repository, "snapshots", "--json"],
      {
        env: resticEnv,
        allowFailure: true,
        shouldCancel,
      },
    );
    if (retry.code !== 0) {
      throw new BackupFilesystemError(
        "repository-initialization",
        "repository-initialization-failed",
      );
    }
  }
}

export function summaryForExistingSnapshot(
  snapshotId: string,
  value: unknown,
): ResticSummary {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new BackupFilesystemError(
      "repository-check",
      "restic-summary-missing",
    );
  const stats = value as Record<string, unknown>;
  for (const key of [
    "files_new",
    "files_changed",
    "files_unmodified",
    "dirs_new",
    "dirs_changed",
    "dirs_unmodified",
    "data_blobs",
    "tree_blobs",
    "data_added",
    "data_added_packed",
    "total_files_processed",
    "total_bytes_processed",
  ]) {
    if (
      typeof stats[key] !== "number" ||
      !Number.isFinite(stats[key]) ||
      (stats[key] as number) < 0
    )
      throw new BackupFilesystemError(
        "repository-check",
        "restic-summary-missing",
      );
  }
  const start = Date.parse(String(stats.backup_start));
  const end = Date.parse(String(stats.backup_end));
  const duration =
    Number.isFinite(start) && Number.isFinite(end) && end >= start
      ? (end - start) / 1000
      : 0;
  return summaryFromRestic({
    ...stats,
    message_type: "summary",
    snapshot_id: snapshotId,
    total_duration: duration,
  })!;
}

/**
 * If an earlier successful Restic run lost its completion ACK, the durable
 * command can be leased again. Reuse the snapshot tagged with its stable
 * backup ID rather than creating a second unrelated snapshot.
 */
async function findExistingBackupSnapshot(
  restic: string,
  repository: string,
  backupId: string,
  env: NodeJS.ProcessEnv,
  shouldCancel: () => Promise<boolean>,
): Promise<BackupFilesystemResult | null> {
  const result = await runProgram(
    restic,
    [
      "-r",
      repository,
      "snapshots",
      "--json",
      "--tag",
      `pluton-backup-${backupId}`,
    ],
    {
      env,
      allowFailure: true,
      shouldCancel,
      timeoutMs: 30_000,
      classifyRepositoryFailure: true,
    },
  );
  if (
    result.repositoryFailure &&
    !["repository-unavailable", "process-failed"].includes(
      result.repositoryFailure,
    )
  ) {
    throw new BackupFilesystemError(
      "repository-check",
      result.repositoryFailure === "authentication-failed"
        ? "target-check-auth-failed"
        : result.repositoryFailure === "access-failed"
          ? "target-check-access-failed"
          : result.repositoryFailure === "transport-failed"
            ? "target-check-transport-failed"
            : "repository-check-failed",
    );
  }
  if (result.code !== 0 || !result.stdout.trim()) return null;
  try {
    const snapshots = JSON.parse(result.stdout) as unknown;
    if (!Array.isArray(snapshots)) return null;
    const snapshot = snapshots
      .slice()
      .reverse()
      .find((value) => {
        if (!value || typeof value !== "object" || Array.isArray(value))
          return false;
        const id = (value as Record<string, unknown>).id;
        return typeof id === "string" && /^[a-f0-9]{8,128}$/i.test(id);
      });
    if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot))
      return null;
    const snapshotId = (snapshot as Record<string, unknown>).id as string;
    if (!(snapshot as Record<string, unknown>).summary)
      throw new BackupFilesystemError(
        "repository-check",
        "restic-summary-missing",
      );
    return {
      snapshotId,
      summary: summaryForExistingSnapshot(
        snapshotId,
        (snapshot as Record<string, unknown>).summary,
      ),
    };
  } catch (error) {
    if (error instanceof BackupFilesystemError) throw error;
    // Treat malformed tool output as a non-match. Repository initialization
    // below remains fail-closed if the target is not a valid managed repo.
    return null;
  }
}

/** Phase 5 confirms the exact full snapshot and artifact, not just an exit code. */
async function confirmLifecycleSnapshot(
  restic: string,
  repository: string,
  payload: BackupFilesystemPayload,
  snapshotId: string,
  env: NodeJS.ProcessEnv,
  shouldCancel: () => Promise<boolean>,
  source: string,
  expectedReport?: LifecycleReport,
): Promise<string> {
  try {
    const result = await runProgram(
      restic,
      [
        "-r",
        repository,
        "snapshots",
        "--json",
        "--tag",
        `pluton-backup-${payload.backupId}`,
      ],
      { env, shouldCancel, timeoutMs: 60_000 },
    );
    const snapshots: unknown = JSON.parse(result.stdout);
    if (!Array.isArray(snapshots)) throw new Error("Invalid snapshots.");
    const matches = snapshots.filter(
      (item) =>
        item &&
        typeof item.id === "string" &&
        /^[a-f0-9]{64}$/.test(item.id) &&
        item.id.startsWith(snapshotId) &&
        Array.isArray(item.tags) &&
        item.tags.includes(`pluton-plan-${payload.planId}`) &&
        item.tags.includes(`pluton-backup-${payload.backupId}`),
    );
    if (matches.length !== 1) throw new Error("Snapshot binding failed.");
    const fullId = matches[0].id as string;
    if (bindsApplicationSource(payload)) {
      if (
        !Array.isArray(matches[0].paths) ||
        !matches[0].paths.includes(source)
      )
        throw new Error("Application source not bound to snapshot.");
      let sourceFound = false;
      await runProgram(
        restic,
        ["-r", repository, "--no-lock", "ls", "--json", fullId, source],
        {
          env,
          shouldCancel,
          timeoutMs: 60_000,
          onJsonLine: async (node) => {
            if (
              node.path === source &&
              (node.type === "dir" || node.type === "file")
            )
              sourceFound = true;
          },
        },
      );
      if (!sourceFound)
        throw new Error("Application source missing from snapshot.");
    }
    for (const db of payload.lifecycle
      ? lifecycleDatabases(payload.lifecycle)
      : []) {
      const dumpPath = `/pluton/database/${db.dumpFilename}`;
      const expected =
        expectedReport?.databases?.find(
          (item) => item.databaseId === db.databaseId,
        ) || expectedReport?.database;
      let files = 0;
      let size: unknown;
      await runProgram(
        restic,
        ["-r", repository, "--no-lock", "ls", "--json", fullId, dumpPath],
        {
          env,
          shouldCancel,
          timeoutMs: 60_000,
          onJsonLine: async (node) => {
            if (node.path === dumpPath && node.type === "file") {
              files++;
              size = node.size;
            }
          },
        },
      );
      if (
        files !== 1 ||
        typeof size !== "number" ||
        !Number.isSafeInteger(size) ||
        size <= 0 ||
        (expected !== undefined &&
          (size !== expected.bytes || expected.path !== dumpPath))
      )
        throw new BackupLifecycleError(
          "snapshot-confirmation",
          "snapshot-confirmation-failed",
          db.databaseId,
          db.engine,
        );
      if (bindsApplicationSource(payload) && expectedReport && !expected) {
        // Local completion receipt lost: recover hashes from the existing tagged
        // snapshot, never rerun hooks/dumps or materialize SQL in the live source.
        const digest = await runLifecycleProcess({
          binary: restic,
          args: ["-r", repository, "--no-lock", "dump", fullId, dumpPath],
          cwd: path.dirname(env.RCLONE_CONFIG!),
          env,
          shouldCancel,
          timeoutSeconds: db.timeoutSeconds,
          hashOutputMaxBytes: size,
        });
        if (digest.bytes !== size)
          throw new BackupLifecycleError(
            "snapshot-confirmation",
            "snapshot-confirmation-failed",
            db.databaseId,
            db.engine,
          );
        (expectedReport.databases ||= []).push({
          databaseId: db.databaseId!,
          engine: db.engine,
          database: db.database,
          path: dumpPath,
          ...digest,
        });
      }
    }
    if (expectedReport?.databases?.length === 1) {
      const { path: artifactPath, bytes, sha256 } = expectedReport.databases[0];
      expectedReport.database = { path: artifactPath, bytes, sha256 };
    }
    return fullId;
  } catch (error) {
    if (error instanceof BackupCancelledError) throw error;
    if (error instanceof BackupLifecycleError) throw error;
    throw new BackupLifecycleError(
      "snapshot-confirmation",
      "snapshot-confirmation-failed",
    );
  }
}

export const DELEGATED_PRIVATE_DIRECTORY_EXCLUDES = [
  "**/.ssh",
  "**/.aws",
  "**/.gnupg",
  "**/.kube",
] as const;

/** Agent-local authority only: no command payload or user exclude can remove these filters. */
export function appendSourceBackupExcludes(
  args: string[],
  userExcludes: string[],
  serverManaged: boolean,
): void {
  for (const exclude of [
    ...userExcludes,
    ...(serverManaged ? DELEGATED_PRIVATE_DIRECTORY_EXCLUDES : []),
  ])
    args.push("--exclude", exclude);
}

export async function executeFilesystemBackup(input: {
  payload: Record<string, unknown>;
  /** Leased-command context that opens version 5 sealed secrets. Never logged. */
  commandSeal?: CommandSealContext;
  config: AgentConfig;
  allowedRoots: string[];
  serverManagedSource?: boolean;
  shouldCancel: () => Promise<boolean>;
  onEvent: (event: Record<string, unknown>) => Promise<void>;
  onStage?: (event: BackupFilesystemStageEvent) => void;
  /** Internal local receipts; never accepted from the remote command payload. */
  successfulSnapshotIds?: string[];
  /** Trusted in-process test budget only; cannot be supplied in a command envelope or increase the deadline. */
  parentLookupTimeoutMs?: number;
}): Promise<BackupFilesystemResult> {
  let stage: BackupFilesystemStage = "payload-validation";
  let temporary: { directory: string; configPath: string } | undefined;
  let operationError: unknown;
  let job: BackupLifecycleJob | undefined;
  let completedResult: BackupFilesystemResult | undefined;
  const setStage = (
    next: BackupFilesystemStage,
    message?: BackupFilesystemStageEvent["message"],
  ): void => {
    stage = next;
    emitStage({ stage: next, message: message || "stage started" });
  };
  const emitStage = (event: BackupFilesystemStageEvent): void => {
    try {
      input.onStage?.(event);
    } catch {
      /* Best-effort journal/progress cannot fail native work. */
    }
  };
  const lifecycleEvent = async (
    checkpoint: LifecycleCheckpoint,
    database?: DatabaseCheckpoint,
  ): Promise<void> => {
    if (checkpoint === "pre-backup-started") stage = "pre-backup";
    if (checkpoint === "database-dump-started") stage = "database-dump";
    if (checkpoint === "database-dump-completed")
      stage = "database-dump-validation";
    if (checkpoint === "post-backup-started") stage = "post-backup";
    emitStage({
      stage,
      message: checkpoint,
      ...(database ? { database } : {}),
    });
    // Stage delivery is best-effort; failure must not undo a completed snapshot/cleanup.
    try {
      await input.onEvent({ lifecycleStage: checkpoint, ...database });
    } catch {
      /* Status polling refreshes the lease as well. */
    }
  };

  try {
    const payload = parseBackupFilesystemPayload(
      input.payload,
      input.commandSeal,
    );
    setStage("payload-validation", "command accepted");

    setStage("source-validation");
    if (
      input.serverManagedSource &&
      sourcePathContainsPrivateDirectory(payload.sourcePath)
    )
      throw new SourceAccessError("source-policy-violation");
    const source = (
      await preflightSource(payload.sourcePath, input.allowedRoots)
    ).resolvedPath;
    if (input.serverManagedSource && sourcePathContainsPrivateDirectory(source))
      throw new SourceAccessError("source-policy-violation");
    const userExcludes = usesVersion4SourceRules(payload)
      ? sourceResticExclusions(source, payload.excludes)
      : payload.excludes;
    emitStage({
      stage: "source-validation",
      message: "source validated",
    });

    setStage("state-validation");
    await assertSourceDoesNotOverlapState(source, input.config.dataDir);
    if (usesVersion4SourceRules(payload)) {
      setStage("source-validation");
      const scan = await preflightSource(
        payload.sourcePath,
        input.allowedRoots,
        {
          scan: true,
          collectProblems: payload.sourceDiagnosticsVersion === 1,
          exclusions: payload.excludes,
          mandatoryExclusions: input.serverManagedSource
            ? DELEGATED_PRIVATE_DIRECTORY_EXCLUDES
            : [],
        },
      );
      if (scan.resolvedPath !== source)
        throw new SourceAccessError("source-symlink-escape");
    }
    if (await input.shouldCancel()) throw new BackupCancelledError();

    setStage("tool-validation");
    let restic = privateBinaryPath(input.config.binDir, "restic");
    let rclone = privateBinaryPath(input.config.binDir, "rclone");
    if (payload.lifecycle) {
      restic = assertRootOwnedPath(await realpath(restic));
      rclone = assertRootOwnedPath(await realpath(rclone));
    }
    await Promise.all([
      access(restic, constants.X_OK),
      access(rclone, constants.X_OK),
    ]);

    const env: NodeJS.ProcessEnv = {
      PATH: payload.lifecycle
        ? `${path.dirname(restic)}:/usr/bin:/bin`
        : `${path.dirname(restic)}${path.delimiter}${process.env.PATH || ""}`,
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
      // Operator-installed trust only; the server never sends CA files.
      const storageCa = assertRootOwnedPath(
        input.config.storageCaFile,
        false,
        true,
      );
      env.SSL_CERT_FILE = storageCa;
      rcloneEnv.SSL_CERT_FILE = storageCa;
    }
    temporary = await writeTemporaryRcloneConfig(
      input.config.dataDir,
      rcloneOptions,
      payload.rclone.type,
    );
    emitStage({
      stage: "temporary-storage-config",
      message: "temporary storage config created",
    });
    env.RCLONE_CONFIG = temporary.configPath;
    rcloneEnv.RCLONE_CONFIG = temporary.configPath;
    const repository = `rclone:${payload.repository.remoteName}:${payload.repository.path}`;

    setStage("repository-check");
    emitStage({
      stage: "repository-check",
      message: "repository check started",
    });
    if (payload.rclone.type === "s3") {
      emitStage({
        stage: "repository-check",
        message: "storage access check started",
      });
      await checkS3RepositoryAccess(
        rclone,
        `${payload.repository.remoteName}:${payload.repository.path}`,
        rcloneEnv,
        input.shouldCancel,
        (diagnostic) =>
          emitStage({
            stage: "repository-check",
            message: "real repository failure",
            diagnostic,
          }),
      );
      emitStage({
        stage: "repository-check",
        message: "storage access verified",
      });
    }
    emitStage({
      stage: "repository-check",
      message: "existing backup snapshot lookup started",
    });
    const existing = await findExistingBackupSnapshot(
      restic,
      repository,
      payload.backupId,
      env,
      input.shouldCancel,
    );
    if (existing) {
      if (payload.lifecycle) {
        setStage("snapshot-confirmation");
        const replayReport: LifecycleReport = {
          warnings: [],
          ...(bindsApplicationSource(payload) ? { databases: [] } : {}),
        };
        const fullId = await confirmLifecycleSnapshot(
          restic,
          repository,
          payload,
          existing.snapshotId,
          env,
          input.shouldCancel,
          source,
          replayReport,
        );
        existing.snapshotId = fullId;
        existing.summary.snapshot_id = fullId;
        existing.lifecycle = replayReport;
      }
      completedResult = existing;
      existing.sourcePaths = [source];
      return existing;
    }
    let artifacts: string[] = [];
    if (payload.lifecycle) {
      setStage("lifecycle-validation");
      if (source === "/pluton" || source.startsWith("/pluton/database"))
        throw new BackupLifecycleError(
          "lifecycle-validation",
          "lifecycle-invalid",
        );
      job = await BackupLifecycleJob.create(
        input.config,
        payload.lifecycle,
        input.shouldCancel,
        lifecycleEvent,
      );
      artifacts = await job.prepare();
      setStage("post-dump-status-check");
      if (await input.shouldCancel()) throw new BackupCancelledError();
    }
    setStage("repository-target-check");
    await ensureManagedRepository(
      payload,
      restic,
      rclone,
      repository,
      env,
      rcloneEnv,
      input.shouldCancel,
      () => {
        setStage(
          "repository-initialization",
          "repository initialization started",
        );
      },
      (result) => setStage("repository-target-check", result),
    );

    // Restic records absolute input paths even for relative DB artifacts. Keep the
    // existing snapshot tree layout/private per-job workspace, but select only a
    // verified successful parent rather than changing/weakening source paths.
    let parent: string | undefined;
    setStage("repository-check", "initial repository verification started");
    const verify = async () => {
      await verifyRepository(
        restic,
        repository,
        env,
        input.shouldCancel,
        (diagnostic) =>
          emitStage({
            stage: "repository-check",
            message: "real repository failure",
            diagnostic,
          }),
      );
      emitStage({
        stage: "repository-check",
        message: "repository verified",
      });
    };
    await verify();
    const successfulIds = (input.successfulSnapshotIds || [])
      .filter((id) => /^[a-f0-9]{64}$/.test(id))
      .slice(-16);
    if (successfulIds.length) {
      setStage("parent-discovery", "parent candidate discovery started");
      try {
        const metadata = await runProgram(
          restic,
          ["-r", repository, ...resticParentDiscoveryArgs(payload.planId)],
          {
            env,
            shouldCancel: input.shouldCancel,
            timeoutMs:
              Number.isSafeInteger(input.parentLookupTimeoutMs) &&
              input.parentLookupTimeoutMs! > 0
                ? Math.min(
                    input.parentLookupTimeoutMs!,
                    PARENT_LOOKUP_TIMEOUT_MS,
                  )
                : PARENT_LOOKUP_TIMEOUT_MS,
            allowFailure: true,
            classifyRepositoryFailure: true,
            maxOutputBytes: 1024 * 1024,
          },
        );
        if (
          metadata.repositoryFailure &&
          metadata.repositoryFailure !== "process-failed"
        ) {
          emitStage({
            stage: "repository-check",
            message: "real repository failure",
            diagnostic: metadata.repositoryFailure,
          });
          throw new BackupFilesystemError(
            "repository-check",
            metadata.repositoryFailure === "authentication-failed"
              ? "target-check-auth-failed"
              : metadata.repositoryFailure === "access-failed"
                ? "target-check-access-failed"
                : metadata.repositoryFailure === "transport-failed"
                  ? "target-check-transport-failed"
                  : "repository-check-failed",
          );
        }
        if (metadata.code !== 0)
          throw new Error("Parent lookup execution failed.");
        if (metadata.outputTruncated)
          throw new SyntaxError("Parent metadata exceeded the bounded output.");
        setStage("parent-verification", "parent metadata verification started");
        const snapshots: unknown = JSON.parse(metadata.stdout);
        if (!Array.isArray(snapshots))
          throw new SyntaxError("Invalid parent metadata collection.");
        parent = compatibleResticParent(snapshots, {
          successfulIds,
          planId: payload.planId,
          source,
          hostname: os.hostname(),
          jobsRoot: path.join(await realpath(input.config.dataDir), "jobs"),
          artifacts,
        });
        emitStage({
          stage: "parent-verification",
          message: parent ? "parent selected" : "no compatible parent",
        });
      } catch (error) {
        if (
          error instanceof BackupCancelledError ||
          error instanceof CommandStatusError ||
          error instanceof BackupFilesystemError
        )
          throw error;
        try {
          if (await input.shouldCancel()) throw new BackupCancelledError();
        } catch (cancelError) {
          if (
            cancelError instanceof BackupCancelledError ||
            cancelError instanceof CommandStatusError
          )
            throw cancelError;
          // Match the runner's existing outage policy; hard repository/process
          // deadlines still apply, and a confirmed cancellation is never ignored.
        }
        if (error instanceof ProgramTimeoutError && error.diagnostic) {
          emitStage({
            stage: "repository-check",
            message: "real repository failure",
            diagnostic: error.diagnostic,
          });
          throw toBackupFilesystemError(error, "repository-check");
        }
        emitStage({
          stage: "parent-discovery",
          message:
            error instanceof ProgramTimeoutError
              ? "parent lookup timeout; checking repository before fallback"
              : error instanceof SyntaxError
                ? "parent metadata invalid; checking repository before fallback"
                : "parent lookup failed; checking repository before fallback",
        });
        setStage("repository-check", "repository reverification started");
        await verify();
        emitStage({
          stage: "parent-discovery",
          message: "parent lookup fallback; continuing without explicit parent",
        });
      }
    } else
      emitStage({
        stage: "parent-discovery",
        message: "no compatible parent",
      });
    setStage("restic-backup");
    // Re-check the selected root after preparation; do not follow a changed symlink.
    if (
      (
        await preflightSource(
          payload.sourcePath,
          input.allowedRoots,
          usesVersion4SourceRules(payload)
            ? {
                scan: true,
                collectProblems: payload.sourceDiagnosticsVersion === 1,
                exclusions: payload.excludes,
                mandatoryExclusions: input.serverManagedSource
                  ? DELEGATED_PRIVATE_DIRECTORY_EXCLUDES
                  : [],
              }
            : {},
        )
      ).resolvedPath !== source
    )
      throw new SourceAccessError("source-symlink-escape");
    if (job) await lifecycleEvent("backup-started");
    emitStage({
      stage: "restic-backup",
      message: "restic backup started",
    });
    let summary: ResticSummary | null = null;
    let lastProgress = 0;
    const args = [
      "-r",
      repository,
      "backup",
      source,
      ...artifacts,
      "--host",
      os.hostname(),
      ...resticParentArgs(parent),
      "--json",
      "--tag",
      `pluton-plan-${payload.planId}`,
      "--tag",
      `pluton-backup-${payload.backupId}`,
    ];
    appendSourceBackupExcludes(
      args,
      userExcludes,
      input.serverManagedSource === true,
    );
    await runProgram(restic, args, {
      env,
      source,
      classifyBackupStorageFailure: payload.rclone.type === "s3",
      ...(usesVersion4SourceRules(payload)
        ? {
            sourceExcluded: compileBackupExclusions([
              ...payload.excludes,
              ...(input.serverManagedSource
                ? DELEGATED_PRIVATE_DIRECTORY_EXCLUDES
                : []),
            ]),
          }
        : {}),
      ...(job ? { cwd: job.workspace, timeoutMs: 24 * 60 * 60 * 1000 } : {}),
      shouldCancel: input.shouldCancel,
      onJsonLine: async (event) => {
        const parsedSummary = summaryFromRestic(event);
        if (parsedSummary) {
          summary = parsedSummary;
          return;
        }
        const progress = progressFromRestic(event);
        if (!progress || Date.now() - lastProgress < PROGRESS_INTERVAL_MS)
          return;
        lastProgress = Date.now();
        await input.onEvent(progress);
      },
    });
    if (!summary)
      throw new BackupFilesystemError(
        "restic-backup",
        "restic-summary-missing",
      );
    // TypeScript cannot observe the assignment performed by the async JSON-line
    // callback, but runProgram awaits that callback chain before returning.
    const completedSummary = summary as ResticSummary;
    if (job) {
      setStage("snapshot-confirmation");
      completedSummary.snapshot_id = await confirmLifecycleSnapshot(
        restic,
        repository,
        payload,
        completedSummary.snapshot_id,
        env,
        input.shouldCancel,
        source,
        job.report,
      );
    }
    const result = {
      snapshotId: completedSummary.snapshot_id,
      sourcePaths: [source],
      summary: completedSummary,
      ...(job ? { lifecycle: job.report } : {}),
    };
    completedResult = result;
    if (job) await lifecycleEvent("backup-completed");
    emitStage({ stage: "restic-backup", message: "backup completed" });
    return result;
  } catch (error) {
    operationError = error;
    throw toBackupFilesystemError(error, stage);
  } finally {
    if (job) await job.cleanup();
    if (temporary) {
      try {
        setStage("cleanup");
        await rm(temporary.directory, { recursive: true, force: true });
      } catch (error) {
        // Never replace the actionable operation failure with a cleanup error.
        // If cleanup is the only failure, return a safe cleanup classification.
        if (completedResult?.lifecycle) {
          completedResult.lifecycle.warnings.push({
            stage: "cleanup",
            code: "cleanup-failed",
          });
        } else if (!operationError) {
          throw toBackupFilesystemError(error, "cleanup");
        }
      }
    }
  }
}
