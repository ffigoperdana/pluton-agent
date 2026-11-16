import crypto from "node:crypto";
import { TextDecoder } from "node:util";

/**
 * Sealed secrets for BACKUP_FILESYSTEM payload version 5 (S3 design section
 * 10.3). The label is the HKDF info, the sealed-field key ID and the prefix of
 * the additional data, so the sealing key never equals the command HMAC key and
 * a sealed blob cannot be replayed into another command or lease.
 */
export const COMMAND_SECRETS_LABEL = "pluton-agent-command-secrets-v1";
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const MAX_CIPHERTEXT_BYTES = 64 * 1024;
const MAX_SECRET_LENGTH = 16_384;
/** Same limits as the lifecycle parser: 1 to 1024 characters, at most 8 databases. */
const MAX_DATABASE_PASSWORD_LENGTH = 1_024;
const MAX_SEALED_DATABASES = 8;
const SEALED_RCLONE_KEYS = ["pass", "access_key_id", "secret_access_key"] as const;
type SealedRcloneKey = (typeof SEALED_RCLONE_KEYS)[number];

/** The leased command the secrets are sealed to. Never logged or persisted. */
export type CommandSealContext = {
  /** The per-Agent secret from identity.json that also verifies the command HMAC. */
  secret: string;
  commandId: string;
  leaseToken: string;
};

export type SealedCommandSecrets = {
  repositoryPassword: string;
  rclone: Partial<Record<SealedRcloneKey, string>>;
  /** Database passwords: `database` for lifecycle shape 1, `databases` keyed by databaseId. */
  lifecycle?: { database?: string; databases?: Record<string, string> };
};

/** One closed refusal for every malformed, tampered, misbound or wrong-key field. */
export class SealedSecretsError extends Error {
  constructor() {
    super("The sealed command secrets are invalid.");
    this.name = "SealedSecretsError";
  }
}

export function deriveCommandSecretsKey(secret: string): Buffer {
  return Buffer.from(
    crypto.hkdfSync(
      "sha256",
      Buffer.from(secret, "utf8"),
      Buffer.alloc(0),
      Buffer.from(COMMAND_SECRETS_LABEL, "utf8"),
      32,
    ),
  );
}

export function commandSecretsAdditionalData(
  commandId: string,
  leaseToken: string,
): Buffer {
  return Buffer.from(
    `${COMMAND_SECRETS_LABEL}\n${commandId}\n${leaseToken}`,
    "utf8",
  );
}

function plainObject(value: unknown): value is Record<string, unknown> {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function exactKeys(value: Record<string, unknown>, keys: string[]): boolean {
  return Object.keys(value).sort().join("\n") === [...keys].sort().join("\n");
}

/** Standard padded base64 only, re-encoded byte for byte (no base64url, whitespace or slack bits). */
function canonicalBase64(value: unknown, exactBytes?: number): Buffer {
  if (
    typeof value !== "string" ||
    !value ||
    value.length > Math.ceil(MAX_CIPHERTEXT_BYTES / 3) * 4 ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(value)
  )
    throw new SealedSecretsError();
  const bytes = Buffer.from(value, "base64");
  if (
    bytes.toString("base64") !== value ||
    (exactBytes !== undefined && bytes.length !== exactBytes)
  )
    throw new SealedSecretsError();
  return bytes;
}

function secretValue(value: unknown): string {
  if (
    typeof value !== "string" ||
    !value ||
    value.length > MAX_SECRET_LENGTH ||
    /[\x00-\x1f\x7f]/.test(value)
  )
    throw new SealedSecretsError();
  return value;
}

function sealedRcloneKey(name: string): name is SealedRcloneKey {
  return (SEALED_RCLONE_KEYS as readonly string[]).includes(name);
}

/** The lifecycle parser's password rule: tabs and newlines are valid, NUL is not. */
function databasePassword(value: unknown): string {
  if (
    typeof value !== "string" ||
    !value ||
    value.length > MAX_DATABASE_PASSWORD_LENGTH ||
    value.includes("\0")
  )
    throw new SealedSecretsError();
  return value;
}

/** Sealed database passwords (S3 design 10.3); present only when the payload has databases. */
function sealedLifecycle(
  value: unknown,
): NonNullable<SealedCommandSecrets["lifecycle"]> {
  if (!plainObject(value)) throw new SealedSecretsError();
  const names = Object.keys(value);
  if (
    !names.length ||
    names.some((name) => name !== "database" && name !== "databases")
  )
    throw new SealedSecretsError();
  const result: NonNullable<SealedCommandSecrets["lifecycle"]> = {};
  if (value.database !== undefined)
    result.database = databasePassword(value.database);
  if (value.databases !== undefined) {
    if (!plainObject(value.databases)) throw new SealedSecretsError();
    const entries = Object.entries(value.databases);
    if (!entries.length || entries.length > MAX_SEALED_DATABASES)
      throw new SealedSecretsError();
    const databases: Record<string, string> = {};
    for (const [databaseId, password] of entries) {
      if (!/^db_[A-Za-z0-9_-]{1,64}$/.test(databaseId))
        throw new SealedSecretsError();
      databases[databaseId] = databasePassword(password);
    }
    result.databases = databases;
  }
  return result;
}

function decrypt(
  context: CommandSealContext,
  nonce: Buffer,
  ciphertext: Buffer,
  tag: Buffer,
): Buffer {
  const key = deriveCommandSecretsKey(context.secret);
  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce, {
      authTagLength: TAG_BYTES,
    });
    decipher.setAAD(
      commandSecretsAdditionalData(context.commandId, context.leaseToken),
    );
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new SealedSecretsError();
  } finally {
    key.fill(0);
  }
}

/**
 * Open the version 5 `sealed` field before any file is written. Any change to
 * the nonce, ciphertext, tag, command ID, lease token or per-Agent secret fails
 * authentication; the plaintext must be exactly the section 10.3 shape.
 */
export function openSealedCommandSecrets(
  sealed: unknown,
  context: CommandSealContext,
): SealedCommandSecrets {
  if (
    !plainObject(sealed) ||
    !exactKeys(sealed, ["alg", "kid", "nonce", "ciphertext", "tag"]) ||
    sealed.alg !== "A256GCM" ||
    sealed.kid !== COMMAND_SECRETS_LABEL ||
    typeof context.secret !== "string" ||
    !context.secret ||
    typeof context.commandId !== "string" ||
    !context.commandId ||
    context.commandId.includes("\n") ||
    typeof context.leaseToken !== "string" ||
    !context.leaseToken ||
    context.leaseToken.includes("\n")
  )
    throw new SealedSecretsError();
  const plaintext = decrypt(
    context,
    canonicalBase64(sealed.nonce, NONCE_BYTES),
    canonicalBase64(sealed.ciphertext),
    canonicalBase64(sealed.tag, TAG_BYTES),
  );
  try {
    const value: unknown = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(plaintext),
    );
    if (
      !plainObject(value) ||
      !(
        exactKeys(value, ["repositoryPassword", "rclone"]) ||
        exactKeys(value, ["repositoryPassword", "rclone", "lifecycle"])
      ) ||
      !plainObject(value.rclone)
    )
      throw new SealedSecretsError();
    const rclone: SealedCommandSecrets["rclone"] = {};
    for (const [name, entry] of Object.entries(value.rclone)) {
      if (!sealedRcloneKey(name)) throw new SealedSecretsError();
      rclone[name] = secretValue(entry);
    }
    return {
      repositoryPassword: secretValue(value.repositoryPassword),
      rclone,
      ...(value.lifecycle !== undefined
        ? { lifecycle: sealedLifecycle(value.lifecycle) }
        : {}),
    };
  } catch {
    throw new SealedSecretsError();
  } finally {
    plaintext.fill(0);
  }
}
