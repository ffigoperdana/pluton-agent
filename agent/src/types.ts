import type { SourceDiagnostics } from "./sourceDiagnostics.js";
export type AgentCommandType =
  | "PING"
  | "INVENTORY_REFRESH"
  | "BACKUP_FILESYSTEM"
  | "SOURCE_ACCESS_VALIDATE"
  | "SOURCE_ACCESS_APPLY"
  | "SOURCE_ACCESS_MODE_SETUP"
  | "RESTORE_FILESYSTEM";

export type SourceAccessValidation = {
  requestedPath: string;
  canonicalPath?: string;
  status: "approved" | "pending-host-approval" | "rejected";
  code?: string;
};

export type SourceAccessReport = {
  version: 1;
  authorizationMode?: "host-approved" | "server-managed";
  delegatedRoots?: string[];
  lastModeSetupRequestId?: string;
  hostPolicyRevision: string;
  effectiveVersion: number;
  approvedRoots: string[];
  effectiveRoots: string[];
  rootStatuses: {
    path: string;
    status: "readable" | "unreadable" | "missing" | "rejected";
    code?: string;
  }[];
  lastAppliedRequestId?: string;
  policyError?: string;
};

/** One host-approved restore root as the heartbeat reports it. No contents, never a selection. */
export type RestoreRootReport = {
  path: string;
  status: "writable" | "unavailable" | "rejected";
  code?: string;
  availableBytes?: number;
  availableInodes?: number;
};

export type RestoreAccessReport = {
  version: 1;
  roots: RestoreRootReport[];
  policyError?: string;
};

export type AgentCapabilities = {
  backupExclusionsVersion?: 1;
  filesystemRootsConfigured: boolean;
  commandTypes: AgentCommandType[];
  backupLifecycleVersion?: 1 | 2;
  databaseEngines?: ("mysql" | "mariadb" | "postgresql")[];
  hooksConfigured?: boolean;
  sourceAccessVersion?: 1;
  sourceAccessModesVersion?: 1;
  /** Repository types this Agent backs up to (S3 design 10.1); always contains "sftp". */
  repositoryBackends?: ("sftp" | "s3")[];
  /** Highest BACKUP_FILESYSTEM payload version this Agent accepts (S3 design 10.1). */
  backupPayloadVersion?: 5;
  /** Agent 0.9.0: RESTORE_FILESYSTEM payload version 1 into a host-approved restore root. */
  restoreFilesystemVersion?: 1;
};

export type AgentInventory = {
  hostname: string;
  os: string;
  architecture: string;
  agentVersion: string;
  resticVersion?: string;
  rcloneVersion?: string;
  uptimeSeconds?: number;
  capabilities: AgentCapabilities;
  sourceAccess?: SourceAccessReport;
  restoreAccess?: RestoreAccessReport;
};

export type StoredCommandCompletion = {
  commandId: string;
  sequence: number;
  success: boolean;
  error?: string;
  /** Closed, non-secret diagnostics for BACKUP_FILESYSTEM failures. */
  failureStage?: string;
  failureCode?: string;
  sourceDiagnostics?: SourceDiagnostics;
  databaseId?: string;
  engine?: "mysql" | "mariadb" | "postgresql";
  /** A bounded, non-secret execution result such as a Restic snapshot ID. */
  result?: Record<string, unknown>;
  cancelled?: boolean;
};

export type StoredAgentIdentity = {
  deviceId: string;
  agentId: string;
  secret: string;
  pollIntervalSeconds: number;
  completedCommands: StoredCommandCompletion[];
};

export type AgentConfig = {
  serverUrl: URL;
  dataDir: string;
  allowedRoots: string[];
  /** Private installer-owned binaries. Never resolve Restic/Rclone from host PATH. */
  binDir?: string;
  /** Administrator-only local configuration; never supplied by a command. */
  hookRoot?: string;
  databaseBinDirs?: string[];
  /** Local administrator-owned maximum. Never accepted from a server command. */
  sourcePolicyFile?: string;
  /** Local administrator-owned restore roots. Never accepted from a server command. */
  restorePolicyFile?: string;
  allowInsecureHttp: boolean;
  caFile?: string;
  /**
   * Operator-installed CA bundle for S3 repositories (PLUTON_AGENT_STORAGE_CA_FILE),
   * passed to Restic and Rclone as SSL_CERT_FILE. Never supplied by a command.
   */
  storageCaFile?: string;
  clientCertFile?: string;
  clientKeyFile?: string;
};

export type AgentCommandEnvelope = {
  id: string;
  type: AgentCommandType;
  payload: Record<string, unknown>;
  idempotencyKey: string;
  leaseExpiresAt: string | null;
  leaseToken: string;
  signatureTimestamp: string;
  signature: string;
};
