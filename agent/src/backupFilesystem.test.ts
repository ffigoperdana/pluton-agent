import assert from "node:assert/strict";
import crypto from "node:crypto";
import { existsSync } from "node:fs";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  BackupFilesystemError,
  executeFilesystemBackup,
  parseBackupFilesystemPayload,
  writeTemporaryRcloneConfig,
} from "./backupFilesystem.js";
import { SealedSecretsError } from "./sealedSecrets.js";
import type { AgentConfig } from "./types.js";

/** The real agent runs on Linux; executable shebang fixtures are not portable on Windows. */
const linuxExecutionTest = process.platform === "win32" ? test.skip : test;

const validPayload = {
  version: 1,
  backupId: "backup-01",
  planId: "plan-01",
  sourcePath: "/srv/example-app",
  excludes: [],
  repository: {
    remoteName: "pluton",
    path: "managed-repositories/example",
    initialize: true,
  },
  rclone: {
    type: "sftp",
    options: {
      host: "sftp.example.internal",
      port: "22",
      user: "backup-user",
      pass: "this-is-a-test-only-password-value",
    },
  },
  repositoryPassword: "test-only-repository-password-value",
};
/** Leased-command context of the S3 design section 10.4 vector. */
const sealContext = {
  secret: "synthetic-agent-secret-0123456789abcdef",
  commandId: "cmd-synthetic-01",
  leaseToken: "0123456789abcdef0123456789abcdef0123456789abcdef",
};
const SEAL_LABEL = "pluton-agent-command-secrets-v1";

/** Independent test sealer (node:crypto only); the Agent itself only opens. */
function sealForTest(
  plaintext: unknown,
  context = sealContext,
  nonce = crypto.randomBytes(12),
) {
  const key = Buffer.from(
    crypto.hkdfSync(
      "sha256",
      Buffer.from(context.secret, "utf8"),
      Buffer.alloc(0),
      Buffer.from(SEAL_LABEL, "utf8"),
      32,
    ),
  );
  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce, {
    authTagLength: 16,
  });
  cipher.setAAD(
    Buffer.from(
      `${SEAL_LABEL}\n${context.commandId}\n${context.leaseToken}`,
      "utf8",
    ),
  );
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(plaintext), "utf8"),
    cipher.final(),
  ]);
  return {
    alg: "A256GCM",
    kid: SEAL_LABEL,
    nonce: nonce.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
  };
}

/** S3 design section 10.4 sealed field, verbatim. */
const vectorSealed = {
  alg: "A256GCM",
  kid: "pluton-agent-command-secrets-v1",
  nonce: "AAECAwQFBgcICQoL",
  ciphertext:
    "jh0qetVE17GJz08s3DXhomumBqDIVOhzX3A4LgVFJeiH9JSKr4qR7OowvN0duifn639ReyzbjXGWiSEWAaymlLJKNnxwbrP+vLmuRdk9vI+wuUG8cJhENnxGV0LXHElNyPLQME0jaSjTfM7T0n9LTBr7V76enQuphACHq53aFDwiyFLa5p/2ML2748FcdivP43U+",
  tag: "pUKJ+stiEzlyVi8BFN6biQ==",
};

/** S3 design section 10.2 example with the 10.4 sealed field. */
const s3Version5Payload = {
  version: 5,
  backupId: "backup-01",
  planId: "plan-01",
  sourcePath: "/srv/example-app",
  excludes: [] as string[],
  repository: {
    remoteName: "pluton",
    path: "bucket-01/pluton/app-01",
    initialize: true,
  },
  rclone: {
    type: "s3",
    options: {
      provider: "Other",
      endpoint: "https://s3.example.internal",
      force_path_style: "true",
      use_accept_encoding_gzip: "false",
      no_check_bucket: "true",
    } as Record<string, string>,
  },
  sealed: vectorSealed,
};

function sftpVersion5Payload(
  sourcePath = "/srv/example-app",
  excludes: string[] = [],
) {
  return {
    version: 5,
    backupId: "backup-01",
    planId: "plan-01",
    sourcePath,
    excludes,
    repository: {
      remoteName: "pluton",
      path: "managed-repositories/example",
      initialize: true,
    },
    rclone: {
      type: "sftp",
      options: {
        host: "sftp.example.internal",
        port: "22",
        user: "backup-user",
      } as Record<string, string>,
    },
    sealed: sealForTest({
      repositoryPassword: validPayload.repositoryPassword,
      rclone: { pass: validPayload.rclone.options.pass },
    }),
  };
}

test("accepts the fixed BACKUP_FILESYSTEM envelope", () => {
  const parsed = parseBackupFilesystemPayload(validPayload);
  assert.equal(parsed.sourcePath, "/srv/example-app");
  assert.deepEqual(parsed.rclone.options, validPayload.rclone.options);
});

test("refuses external-SSH and generic-command SFTP options", () => {
  assert.throws(
    () =>
      parseBackupFilesystemPayload({
        ...validPayload,
        rclone: {
          ...validPayload.rclone,
          options: {
            ...validPayload.rclone.options,
            ssh: "ssh -o ProxyCommand=unsafe",
          },
        },
      }),
    /unsupported option/,
  );
});

test("refuses traversal, control characters, and unexpected command fields", () => {
  assert.throws(
    () =>
      parseBackupFilesystemPayload({
        ...validPayload,
        repository: { ...validPayload.repository, path: "managed/../other" },
      }),
    /traversal/,
  );
  assert.throws(
    () =>
      parseBackupFilesystemPayload({
        ...validPayload,
        sourcePath: "/srv/example\u0000app",
      }),
    /invalid/,
  );
  assert.throws(
    () =>
      parseBackupFilesystemPayload({
        ...validPayload,
        arbitraryShell: "never",
      }),
    /unsupported fields/,
  );
  assert.throws(
    () =>
      parseBackupFilesystemPayload({
        ...validPayload,
        parentLookupTimeoutMs: 0,
      }),
    /unsupported fields/,
  );
});

test("payload v5: opens the sealed S3 vector and merges the keys into the allowlisted options", () => {
  const parsed = parseBackupFilesystemPayload(s3Version5Payload, sealContext);
  assert.equal(parsed.version, 5);
  assert.equal(parsed.rclone.type, "s3");
  assert.deepEqual(parsed.rclone.options, {
    provider: "Other",
    endpoint: "https://s3.example.internal",
    force_path_style: "true",
    use_accept_encoding_gzip: "false",
    no_check_bucket: "true",
    access_key_id: "SYNTHETICKEY01",
    secret_access_key: "synthetic-secret-key-01",
  });
  assert.equal(parsed.repositoryPassword, "synthetic-repository-password-01");
  assert.equal(parsed.repository.path, "bucket-01/pluton/app-01");
});

test("payload v5: the SFTP password travels sealed and is merged before obscuring", () => {
  const parsed = parseBackupFilesystemPayload(
    sftpVersion5Payload(),
    sealContext,
  );
  assert.equal(parsed.rclone.type, "sftp");
  assert.deepEqual(parsed.rclone.options, {
    host: "sftp.example.internal",
    port: "22",
    user: "backup-user",
    pass: validPayload.rclone.options.pass,
  });
  assert.equal(parsed.repositoryPassword, validPayload.repositoryPassword);
});

test("payload v5: tampered, misbound or unkeyed sealed fields refuse the command", () => {
  for (const context of [
    { ...sealContext, commandId: "cmd-synthetic-02" },
    { ...sealContext, leaseToken: "f".repeat(48) },
    { ...sealContext, secret: "synthetic-other-agent-secret" },
  ])
    assert.throws(
      () => parseBackupFilesystemPayload(s3Version5Payload, context),
      SealedSecretsError,
    );
  const ciphertext = Buffer.from(vectorSealed.ciphertext, "base64");
  ciphertext[10] ^= 1;
  assert.throws(
    () =>
      parseBackupFilesystemPayload(
        {
          ...s3Version5Payload,
          sealed: {
            ...vectorSealed,
            ciphertext: ciphertext.toString("base64"),
          },
        },
        sealContext,
      ),
    SealedSecretsError,
  );
  assert.throws(
    () => parseBackupFilesystemPayload(s3Version5Payload),
    /leased command context/,
  );
  const { sealed: _sealed, ...unsealed } = s3Version5Payload;
  assert.throws(
    () => parseBackupFilesystemPayload(unsealed, sealContext),
    SealedSecretsError,
  );
});

test("payload v5: plaintext credentials and a top-level repository password are refused", () => {
  assert.throws(
    () =>
      parseBackupFilesystemPayload(
        {
          ...s3Version5Payload,
          repositoryPassword: "synthetic-repository-password-01",
        },
        sealContext,
      ),
    /must be sealed/,
  );
  for (const key of ["access_key_id", "secret_access_key", "pass"])
    assert.throws(
      () =>
        parseBackupFilesystemPayload(
          {
            ...s3Version5Payload,
            rclone: {
              type: "s3",
              options: {
                ...s3Version5Payload.rclone.options,
                [key]: "synthetic-plaintext",
              },
            },
          },
          sealContext,
        ),
      /must be sealed/,
    );
  assert.throws(
    () =>
      parseBackupFilesystemPayload(
        {
          ...sftpVersion5Payload(),
          rclone: {
            type: "sftp",
            options: {
              host: "sftp.example.internal",
              user: "backup-user",
              pass: "synthetic-plaintext",
            },
          },
        },
        sealContext,
      ),
    /must be sealed/,
  );
  assert.throws(
    () =>
      parseBackupFilesystemPayload(
        {
          ...s3Version5Payload,
          sealed: sealForTest({
            repositoryPassword: "synthetic-repository-password-01",
            rclone: { access_key_id: "SYNTHETICKEY01" },
          }),
        },
        sealContext,
      ),
    SealedSecretsError,
  );
  assert.throws(
    () =>
      parseBackupFilesystemPayload(
        {
          ...sftpVersion5Payload(),
          sealed: sealForTest({
            repositoryPassword: validPayload.repositoryPassword,
            rclone: {
              pass: validPayload.rclone.options.pass,
              access_key_id: "SYNTHETICKEY01",
            },
          }),
        },
        sealContext,
      ),
    SealedSecretsError,
  );
});

test("payload v5: S3 options are allowlisted and HTTPS-only with path style and no transfer compression", () => {
  const base = s3Version5Payload.rclone.options;
  const withOptions = (options: Record<string, string>) => ({
    ...s3Version5Payload,
    rclone: { type: "s3", options },
  });
  assert.equal(
    parseBackupFilesystemPayload(
      withOptions({
        ...base,
        region: "us-east-1",
        location_constraint: "us-east-1",
        acl: "private",
      }),
      sealContext,
    ).rclone.options.region,
    "us-east-1",
  );
  const cases: [Record<string, string>, RegExp][] = [
    [{ ...base, env_auth: "true" }, /unsupported option/],
    [
      { ...base, shared_credentials_file: "/root/.aws/credentials" },
      /unsupported option/,
    ],
    [{ ...base, endpoint: "http://s3.example.internal" }, /HTTPS origin/],
    [
      { ...base, endpoint: "https://s3.example.internal/bucket-01" },
      /HTTPS origin/,
    ],
    [
      { ...base, endpoint: "https://user:secret@s3.example.internal" },
      /HTTPS origin/,
    ],
    [{ ...base, endpoint: "https://s3.example.internal:443" }, /HTTPS origin/],
    [
      {
        provider: "Other",
        endpoint: base.endpoint,
        use_accept_encoding_gzip: "false",
      },
      /path-style/,
    ],
    [{ ...base, force_path_style: "false" }, /path-style/],
    [{ ...base, use_accept_encoding_gzip: "true" }, /transfer compression/],
    [
      { provider: "Other", endpoint: base.endpoint, force_path_style: "true" },
      /transfer compression/,
    ],
    [{ ...base, no_check_bucket: "yes" }, /bucket check/],
    [{ ...base, region: "us-east-1\nexec" }, /invalid/],
    [{ ...base, acl: "private;x" }, /invalid/],
  ];
  for (const [options, message] of cases)
    assert.throws(
      () => parseBackupFilesystemPayload(withOptions(options), sealContext),
      message,
      JSON.stringify(options),
    );
});

test("payload v5: S3 repositories must be a prefix inside a bucket", () => {
  for (const repositoryPath of [
    "bucket-01",
    "/bucket-01/app-01",
    "bucket-01//app-01",
    "bucket-01/./app-01",
    "bucket-01/app-01/",
    "bucket-01\\app-01",
    "bucket-01/../app-01",
  ])
    assert.throws(
      () =>
        parseBackupFilesystemPayload(
          {
            ...s3Version5Payload,
            repository: {
              ...s3Version5Payload.repository,
              path: repositoryPath,
            },
          },
          sealContext,
        ),
      /prefix inside a bucket|traversal/,
      repositoryPath,
    );
});

test("payload v5: versions 1 to 4 stay SFTP-only and newer versions are refused", () => {
  assert.throws(
    () =>
      parseBackupFilesystemPayload({
        ...validPayload,
        version: 4,
        rclone: { type: "s3", options: s3Version5Payload.rclone.options },
      }),
    /Only SFTP storage/,
  );
  assert.throws(
    () =>
      parseBackupFilesystemPayload(
        { ...s3Version5Payload, version: 6 },
        sealContext,
      ),
    /unsupported/,
  );
  assert.throws(
    () =>
      parseBackupFilesystemPayload(
        { ...s3Version5Payload, rclone: { type: "b2", options: {} } },
        sealContext,
      ),
    /Storage type is unsupported/,
  );
});

test("payload v5: accepts sourceDiagnosticsVersion as today and refuses any trust setting in the payload", () => {
  assert.equal(
    parseBackupFilesystemPayload(
      { ...s3Version5Payload, sourceDiagnosticsVersion: 1 },
      sealContext,
    ).sourceDiagnosticsVersion,
    1,
  );
  assert.equal(
    parseBackupFilesystemPayload(
      { ...sftpVersion5Payload(), sourceDiagnosticsVersion: 1 },
      sealContext,
    ).sourceDiagnosticsVersion,
    1,
  );
  assert.equal(
    parseBackupFilesystemPayload(s3Version5Payload, sealContext)
      .sourceDiagnosticsVersion,
    undefined,
  );
  assert.throws(
    () =>
      parseBackupFilesystemPayload(
        { ...s3Version5Payload, sourceDiagnosticsVersion: 2 },
        sealContext,
      ),
    /Source diagnostics version is unsupported/,
  );
  // Trust comes only from the Agent's own PLUTON_AGENT_STORAGE_CA_FILE (spec 6.1 point 2).
  for (const key of ["ca_cert", "no_check_certificate", "SSL_CERT_FILE"])
    assert.throws(
      () =>
        parseBackupFilesystemPayload(
          {
            ...s3Version5Payload,
            rclone: {
              type: "s3",
              options: {
                ...s3Version5Payload.rclone.options,
                [key]: "/etc/ssl/certs/synthetic.pem",
              },
            },
          },
          sealContext,
        ),
      /unsupported option/,
      key,
    );
  for (const field of ["trust", "storageCaFile", "caFile"])
    assert.throws(
      () =>
        parseBackupFilesystemPayload(
          { ...s3Version5Payload, [field]: "/etc/ssl/certs/synthetic.pem" },
          sealContext,
        ),
      /unsupported fields/,
      field,
    );
});

test("payload v5: keeps the version 4 exclusion grammar and the optional lifecycle", () => {
  assert.deepEqual(
    parseBackupFilesystemPayload(
      { ...s3Version5Payload, excludes: [" .cache/ ", "node_modules"] },
      sealContext,
    ).excludes,
    [".cache", "node_modules"],
  );
  assert.throws(() =>
    parseBackupFilesystemPayload(
      { ...s3Version5Payload, excludes: ["../escape"] },
      sealContext,
    ),
  );
  assert.equal(
    parseBackupFilesystemPayload(s3Version5Payload, sealContext).lifecycle,
    undefined,
  );
  assert.equal(
    parseBackupFilesystemPayload(
      {
        ...sftpVersion5Payload(),
        lifecycle: {
          version: 1,
          preHook: { id: "prepare", args: [], timeoutSeconds: 5 },
        },
      },
      sealContext,
    ).lifecycle?.version,
    1,
  );
});

/** A version 2 lifecycle database entry without its password (sealed in version 5). */
const databaseEntry = {
  databaseId: "db_one",
  engine: "mysql",
  host: "127.0.0.1",
  port: 3306,
  tls: "local",
  database: "example_db",
  username: "backup_reader",
  dumpFilename: "app.sql",
  timeoutSeconds: 60,
  maxDumpBytes: 4 * 1024 * 1024,
  includeRoutines: false,
  includeEvents: false,
};

function s3SealedWithDatabases(lifecycle: unknown) {
  return sealForTest({
    repositoryPassword: "synthetic-repository-password-01",
    rclone: {
      access_key_id: "SYNTHETICKEY01",
      secret_access_key: "synthetic-secret-key-01",
    },
    lifecycle,
  });
}

test("payload v5: database passwords are sealed per lifecycle shape and restored before use", () => {
  const twoDatabases = {
    version: 2,
    databases: [
      databaseEntry,
      {
        ...databaseEntry,
        databaseId: "db_two",
        database: "example_db2",
        dumpFilename: "two.sql",
      },
    ],
  };
  const parsed = parseBackupFilesystemPayload(
    {
      ...s3Version5Payload,
      lifecycle: twoDatabases,
      sealed: s3SealedWithDatabases({
        databases: {
          db_one: "synthetic-db-password-01",
          db_two: "synthetic-db\tpassword\n02",
        },
      }),
    },
    sealContext,
  );
  assert.equal(parsed.lifecycle?.version, 2);
  assert.deepEqual(
    parsed.lifecycle?.databases?.map((db) => [db.databaseId, db.password]),
    [
      ["db_one", "synthetic-db-password-01"],
      ["db_two", "synthetic-db\tpassword\n02"],
    ],
  );
  assert.ok(
    twoDatabases.databases.every((db) => !("password" in db)),
    "The signed payload object must not be modified.",
  );
  const { databaseId: _databaseId, ...singleDatabase } = databaseEntry;
  assert.equal(
    parseBackupFilesystemPayload(
      {
        ...sftpVersion5Payload(),
        lifecycle: { version: 1, database: singleDatabase },
        sealed: sealForTest({
          repositoryPassword: validPayload.repositoryPassword,
          rclone: { pass: validPayload.rclone.options.pass },
          lifecycle: { database: "synthetic-db-password-01" },
        }),
      },
      sealContext,
    ).lifecycle?.database?.password,
    "synthetic-db-password-01",
  );
  const refusals: [Record<string, unknown>, RegExp][] = [
    [
      {
        ...s3Version5Payload,
        lifecycle: {
          version: 2,
          databases: [{ ...databaseEntry, password: "synthetic-plaintext" }],
        },
        sealed: s3SealedWithDatabases({
          databases: { db_one: "synthetic-db-password-01" },
        }),
      },
      /database passwords must be sealed/,
    ],
    [
      {
        ...s3Version5Payload,
        lifecycle: twoDatabases,
        sealed: s3SealedWithDatabases({
          databases: { db_one: "synthetic-db-password-01" },
        }),
      },
      /no sealed password/,
    ],
    [{ ...s3Version5Payload, lifecycle: twoDatabases }, /no sealed password/],
    [
      {
        ...s3Version5Payload,
        lifecycle: twoDatabases,
        sealed: s3SealedWithDatabases({ database: "synthetic-db-password-01" }),
      },
      /no sealed password/,
    ],
    [
      {
        ...s3Version5Payload,
        lifecycle: twoDatabases,
        sealed: s3SealedWithDatabases({
          databases: {
            db_one: "synthetic-db-password-01",
            db_two: "synthetic-db-password-02",
            db_three: "synthetic-db-password-03",
          },
        }),
      },
      /no matching database/,
    ],
    [
      {
        ...s3Version5Payload,
        sealed: s3SealedWithDatabases({ database: "synthetic-db-password-01" }),
      },
      /no matching database/,
    ],
    [
      {
        ...s3Version5Payload,
        lifecycle: {
          version: 1,
          preHook: { id: "prepare", args: [], timeoutSeconds: 5 },
        },
        sealed: s3SealedWithDatabases({ database: "synthetic-db-password-01" }),
      },
      /no matching database/,
    ],
  ];
  for (const [candidate, message] of refusals)
    assert.throws(
      () => parseBackupFilesystemPayload(candidate, sealContext),
      message,
    );
  // Versions 1 to 4 keep the plain password unchanged.
  assert.equal(
    parseBackupFilesystemPayload({
      ...validPayload,
      version: 3,
      lifecycle: {
        version: 2,
        databases: [{ ...databaseEntry, password: "synthetic-db-password-01" }],
      },
    }).lifecycle?.databases?.[0].password,
    "synthetic-db-password-01",
  );
});

for (const mode of [
  "valid",
  "missing-receipt",
  "incompatible",
  "foreign-repository",
  "malformed",
  "process-failed",
  "output-limit",
  "timeout",
  "timeout-control-plane-outage",
  "timeout-parent-exit",
  "timeout-unavailable",
  "auth",
  "access",
  "transport",
  "invalid-config",
  "parent-auth",
  "parent-access",
  "parent-transport",
  "parent-corrupt",
  "parent-timeout-auth",
  "parent-timeout-corrupt",
  "cancelled",
]) {
  linuxExecutionTest(
    `parent discovery ${mode}: verified selection/fallback remains isolated and sanitized`,
    async () => {
      const fixture = await createExecutionFixture("");
      const stages: import("./backupFilesystem.js").BackupFilesystemStageEvent[] =
        [];
      const id = "a".repeat(64);
      try {
        await writeFile(
          path.join(fixture.binDir, "restic"),
          `#!/usr/bin/env node
import { appendFileSync, writeFileSync, existsSync } from 'node:fs';
import { spawn } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
const args = process.argv.slice(2), mode = ${JSON.stringify(mode)};
const state = path.dirname(path.dirname(process.env.RCLONE_CONFIG));
appendFileSync(path.join(state, 'restic-calls'), JSON.stringify(args)+'\\n');
if (args.includes('cat')) {
  if (mode === 'auth') { process.stderr.write('wrong password'); process.exit(12); }
  if (mode === 'access') { process.stderr.write('permission denied'); process.exit(1); }
  if (mode === 'transport') { process.stderr.write('connection refused'); process.exit(1); }
  if (mode === 'timeout-unavailable' && existsSync(path.join(state,'discovery'))) process.exit(10);
  console.log(JSON.stringify({ version: mode === 'invalid-config' ? 999 : 2, id: 'c'.repeat(64) }));
} else if (args.includes('--latest')) {
  writeFileSync(path.join(state,'discovery'), 'started');
  if (mode === 'parent-auth') { process.stderr.write('wrong password'); process.exit(12); }
  if (mode === 'parent-access') { process.stderr.write('permission denied'); process.exit(1); }
  if (mode === 'parent-transport') { process.stderr.write('connection refused'); process.exit(1); }
  if (mode === 'parent-corrupt') { process.stderr.write('ciphertext verification failed'); process.exit(1); }
  if (['timeout','timeout-control-plane-outage','timeout-parent-exit','timeout-unavailable','parent-timeout-auth','parent-timeout-corrupt','cancelled'].includes(mode)) {
    if (mode === 'parent-timeout-auth') process.stderr.write('wrong password');
    if (mode === 'parent-timeout-corrupt') process.stderr.write('ciphertext verification failed');
    const child=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'inherit'});
    writeFileSync(path.join(state,'child-pid'),String(child.pid));
    if (mode === 'timeout-parent-exit') process.exit(0);
    setInterval(()=>{},1000);
  } else if (mode === 'malformed') console.log('not JSON');
  else if (mode === 'process-failed') { process.stderr.write(process.env.RESTIC_PASSWORD); process.exit(1); }
  else if (mode === 'output-limit') console.log('['+' '.repeat(2*1024*1024)+']');
  else console.log(JSON.stringify(mode === 'foreign-repository' ? [] : [{id:'a'.repeat(64),tree:'b'.repeat(64),hostname:os.hostname(),time:new Date(Date.now()-1000).toISOString(),tags:[mode==='incompatible'?'pluton-plan-plan-other':'pluton-plan-plan-01','pluton-backup-backup-old'],paths:[${JSON.stringify(fixture.source)}]}]));
} else if (args.includes('snapshots')) console.log('[]');
else if (args.includes('backup')) console.log(JSON.stringify({message_type:'summary',snapshot_id:'d'.repeat(64),files_new:0,files_changed:0,files_unmodified:0,dirs_new:0,dirs_changed:0,dirs_unmodified:0,data_blobs:0,tree_blobs:0,data_added:0,data_added_packed:0,total_files_processed:0,total_bytes_processed:0,total_duration:0}));
`,
        );
        let cancelled = false;
        let parentStarted = false;
        const input = {
          ...executionInput(fixture),
          successfulSnapshotIds: mode === "missing-receipt" ? [] : [id],
          parentLookupTimeoutMs: 300,
          shouldCancel: async () => {
            if (mode === "timeout-control-plane-outage" && parentStarted)
              throw new Error("Synthetic control-plane outage.");
            return cancelled;
          },
          onStage: (
            event: import("./backupFilesystem.js").BackupFilesystemStageEvent,
          ) => {
            stages.push(event);
            if (event.stage === "parent-discovery") parentStarted = true;
            if (mode === "cancelled" && event.stage === "parent-discovery")
              cancelled = true;
          },
        };
        const fatal = [
          "timeout-unavailable",
          "auth",
          "access",
          "transport",
          "invalid-config",
          "parent-auth",
          "parent-access",
          "parent-transport",
          "parent-corrupt",
          "parent-timeout-auth",
          "parent-timeout-corrupt",
          "cancelled",
        ].includes(mode);
        if (fatal) {
          await assert.rejects(
            executeFilesystemBackup(input),
            (error: unknown) => {
              assert(error instanceof BackupFilesystemError);
              assert.equal(error.stage, "repository-check");
              assert.equal(
                error.code,
                mode === "cancelled"
                  ? "cancelled"
                  : mode === "auth" || mode.endsWith("auth")
                    ? "target-check-auth-failed"
                    : mode === "access" || mode.endsWith("access")
                      ? "target-check-access-failed"
                      : mode === "transport" || mode.endsWith("transport")
                        ? "target-check-transport-failed"
                        : "repository-check-failed",
              );
              return true;
            },
          );
        } else await executeFilesystemBackup(input);
        const calls = await readCalls(
          path.join(fixture.dataDir, "restic-calls"),
        );
        const backup = calls.find((args) => args.includes("backup"));
        assert.equal(!!backup, !fatal);
        if (backup) {
          if (mode === "valid")
            assert.equal(backup[backup.indexOf("--parent") + 1], id);
          else {
            assert(!backup.includes("--parent"));
            assert.equal(
              backup[backup.indexOf("--group-by") + 1],
              "host,paths,tags",
            );
            assert(
              backup.includes("pluton-plan-plan-01") &&
                backup.includes("pluton-backup-backup-01"),
            );
          }
        }
        const lookup = calls.find((args) => args.includes("--latest"));
        if (lookup) {
          assert(!lookup.includes(id));
          assert(lookup.includes("pluton-plan-plan-01"));
          assert(lookup.includes("--no-lock"));
        }
        if (mode.startsWith("parent-") && mode !== "timeout-parent-exit") {
          assert(
            !stages.some(
              (event) =>
                event.message ===
                "parent lookup fallback; continuing without explicit parent",
            ),
          );
          assert(
            stages.some((event) => event.message === "real repository failure"),
          );
        }
        if (
          [
            "timeout",
            "timeout-control-plane-outage",
            "timeout-parent-exit",
            "malformed",
            "process-failed",
            "output-limit",
          ].includes(mode)
        ) {
          assert.equal(calls.filter((args) => args.includes("cat")).length, 2);
          assert(
            stages.some(
              (event) =>
                event.message ===
                "parent lookup fallback; continuing without explicit parent",
            ),
          );
        }
        if (mode.includes("timeout") || mode === "cancelled") {
          const pid = Number(
            await readFile(path.join(fixture.dataDir, "child-pid"), "utf8"),
          );
          for (let i = 0; i < 30; i++) {
            try {
              process.kill(pid, 0);
            } catch {
              break;
            }
            await new Promise((resolve) => setTimeout(resolve, 25));
          }
          assert.throws(() => process.kill(pid, 0), /ESRCH/);
        }
        assert(
          !JSON.stringify(stages).includes(validPayload.repositoryPassword),
        );
        assert(
          !JSON.stringify(stages).includes(validPayload.rclone.options.pass),
        );
        assert.deepEqual(
          (await readdir(fixture.dataDir)).filter((name) =>
            name.startsWith("rclone-"),
          ),
          [],
        );
      } finally {
        await rm(fixture.root, { recursive: true, force: true });
      }
    },
  );
}

const permissionTest = process.platform === "win32" ? test.skip : test;

permissionTest("creates a private temporary Rclone config", async () => {
  const dataDir = await mkdtemp(path.join(os.tmpdir(), "pluton-agent-config-"));
  try {
    const temporary = await writeTemporaryRcloneConfig(dataDir, {
      host: "sftp.example.internal",
      pass: "obscured-test-password",
      user: "backup-user",
    });
    const directoryMode = (await stat(temporary.directory)).mode & 0o777;
    const fileMode = (await stat(temporary.configPath)).mode & 0o777;
    const contents = await readFile(temporary.configPath, "utf8");
    assert.equal(directoryMode, 0o700);
    assert.equal(fileMode, 0o600);
    assert.match(contents, /type = sftp/);
    assert.match(contents, /pass = obscured-test-password/);
    await rm(temporary.directory, { recursive: true, force: true });
    await assert.rejects(() => stat(temporary.directory));
  } finally {
    await rm(dataDir, { recursive: true, force: true });
  }
});

async function createExecutionFixture(
  listing: string,
  exitCode = 0,
  diagnostics = "",
): Promise<{
  root: string;
  source: string;
  dataDir: string;
  binDir: string;
}> {
  const root = await mkdtemp(path.join(os.tmpdir(), "pluton-agent-execution-"));
  const source = path.join(root, "source");
  const dataDir = path.join(root, "state");
  const binDir = path.join(root, "bin");
  await Promise.all([mkdir(source), mkdir(dataDir), mkdir(binDir)]);
  const rclone = `#!/usr/bin/env node
import { appendFileSync, readFileSync } from "node:fs";
import path from "node:path";
const args = process.argv.slice(2);
const config = process.env.RCLONE_CONFIG || "";
const state = config ? path.dirname(path.dirname(config)) : "";
const log = state ? path.join(state, "rclone.calls") : "";
if (log) appendFileSync(log, JSON.stringify(args) + "\\n");
if (args[0] === "obscure") {
  let input = "";
  process.stdin.on("data", chunk => input += chunk);
  process.stdin.on("end", () => process.stdout.write("obscured-test-value\\n"));
} else if (args[0] === "lsf") {
  const contents = readFileSync(config, "utf8");
  if (state) appendFileSync(path.join(state, "rclone.config-check"), contents.includes("obscured-test-value") ? "obscured\\n" : "plaintext\\n");
  process.stdout.write(${JSON.stringify(listing)});
  process.stderr.write(${JSON.stringify(diagnostics)});
  process.exitCode = ${exitCode};
}
`;
  const restic = `#!/usr/bin/env node
import { appendFileSync } from "node:fs";
import path from "node:path";
const args = process.argv.slice(2);
const config = process.env.RCLONE_CONFIG || "";
const state = config ? path.dirname(path.dirname(config)) : "";
const log = state ? path.join(state, "restic-calls") : "";
if (log) appendFileSync(log, JSON.stringify(args) + "\\n");
if (args.includes("cat") && args.includes("config")) { console.log(JSON.stringify({version:2,id:"c".repeat(64)})); process.exit(0); }
if (args.includes("snapshots")) process.exit(1);
if (args.includes("init")) process.exit(0);
if (args.includes("backup")) process.stdout.write(JSON.stringify({message_type:"summary",snapshot_id:"abcdef0123456789",files_new:0,files_changed:0,files_unmodified:0,dirs_new:0,dirs_changed:0,dirs_unmodified:0,data_blobs:0,tree_blobs:0,data_added:0,data_added_packed:0,total_files_processed:0,total_bytes_processed:0,total_duration:0}) + "\\n");
`;
  await writeFile(path.join(binDir, "rclone"), rclone);
  await writeFile(path.join(binDir, "restic"), restic);
  await Promise.all([
    chmod(path.join(binDir, "rclone"), 0o755),
    chmod(path.join(binDir, "restic"), 0o755),
  ]);
  return { root, source, dataDir, binDir };
}

function executionInput(
  fixture: Awaited<ReturnType<typeof createExecutionFixture>>,
) {
  return {
    payload: { ...validPayload, sourcePath: fixture.source },
    config: {
      serverUrl: new URL("https://example.invalid"),
      dataDir: fixture.dataDir,
      allowedRoots: [fixture.source],
      binDir: fixture.binDir,
      allowInsecureHttp: false,
    },
    allowedRoots: [fixture.source],
    shouldCancel: async () => false,
    onEvent: async () => undefined,
  };
}

async function readCalls(file: string): Promise<string[][]> {
  return (await readFile(file, "utf8"))
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as string[]);
}

for (const status of [0, 3])
  linuxExecutionTest(
    `structured Restic source errors remain failed with bounded diagnostics even with exit ${status}`,
    async () => {
      const fixture = await createExecutionFixture("");
      try {
        const record = JSON.stringify({
          message_type: "error",
          during: "archival",
          item: path.join(fixture.source, "app/logs/id_rsa"),
          error: {
            message:
              "open: permission denied; synthetic private provider detail",
          },
        });
        await writeFile(
          path.join(fixture.binDir, "restic"),
          `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args.includes('cat')) console.log(JSON.stringify({version:2,id:'c'.repeat(64)}));
if (args.includes('backup')) {
  const line = ${JSON.stringify(record)};
  process.stderr.write(line.slice(0, 12));
  setTimeout(() => { process.stderr.write(line.slice(12)); process.exitCode = ${status}; }, 10);
}
`,
        );
        await assert.rejects(
          executeFilesystemBackup({
            ...executionInput(fixture),
            payload: {
              ...executionInput(fixture).payload,
              sourceDiagnosticsVersion: 1,
            },
          }),
          (error: unknown) => {
            assert.ok(error instanceof BackupFilesystemError);
            assert.equal(error.stage, "restic-backup");
            assert.equal(error.code, "source-entry-inaccessible");
            assert.deepEqual(error.sourceDiagnostics?.entries, [
              {
                relativePath: "app/logs/id_rsa",
                entryType: "unknown",
                errno: "EACCES",
                excluded: false,
              },
            ]);
            assert.ok(
              !JSON.stringify(error.sourceDiagnostics).includes(
                "synthetic private provider detail",
              ),
            );
            assert.ok(!error.message.includes("id_rsa"));
            return true;
          },
        );
      } finally {
        await rm(fixture.root, { recursive: true, force: true });
      }
    },
  );

linuxExecutionTest(
  "v4 workflow prunes excluded inaccessible entries, anchors actual argv and preserves mandatory private filters",
  async () => {
    const fixture = await createExecutionFixture("");
    const denied = path.join(fixture.source, "node_modules"),
      privateDirectory = path.join(fixture.source, ".ssh");
    await mkdir(denied);
    await mkdir(privateDirectory);
    await chmod(denied, 0);
    await chmod(privateDirectory, 0);
    try {
      const input = executionInput(fixture);
      const result = await executeFilesystemBackup({
        ...input,
        serverManagedSource: true,
        payload: {
          ...input.payload,
          version: 4,
          excludes: ["node_modules/", "*.sql"],
        },
      });
      assert(result.snapshotId);
      const calls = await readCalls(path.join(fixture.dataDir, "restic-calls"));
      const argv = calls.find((args) => args.includes("backup"))!;
      assert(argv.includes(`${fixture.source}/**/node_modules`));
      assert(argv.includes(`${fixture.source}/**/*.sql`));
      assert(argv.includes("**/.ssh"));
      assert(!argv.includes("*.sql"));
      await writeFile(
        path.join(fixture.source, "included"),
        "synthetic included",
      );
      await chmod(path.join(fixture.source, "included"), 0);
      await assert.rejects(
        executeFilesystemBackup({
          ...input,
          payload: {
            ...input.payload,
            version: 4,
            excludes: ["node_modules/", ".ssh/"],
          },
        }),
        (error: unknown) =>
          error instanceof BackupFilesystemError &&
          error.code === "source-entry-inaccessible",
      );
      await chmod(path.join(fixture.source, "included"), 0o600);
      await assert.rejects(
        executeFilesystemBackup({
          ...input,
          shouldCancel: async () => true,
          payload: {
            ...input.payload,
            version: 4,
            excludes: ["node_modules/", ".ssh/"],
          },
        }),
        (error: unknown) =>
          error instanceof BackupFilesystemError && error.code === "cancelled",
      );
      assert.equal(
        (await readCalls(path.join(fixture.dataDir, "restic-calls"))).filter(
          (args) => args.includes("backup"),
        ).length,
        1,
      );
    } finally {
      await chmod(denied, 0o700);
      await chmod(privateDirectory, 0o700);
      await rm(fixture.root, { recursive: true, force: true });
    }
  },
);

linuxExecutionTest(
  "reports a non-empty managed target before Restic init or backup",
  async () => {
    const fixture = await createExecutionFixture("repo\n");
    const stages: string[] = [];
    try {
      await assert.rejects(
        () =>
          executeFilesystemBackup({
            ...executionInput(fixture),
            onStage: (event) => stages.push(`${event.stage}:${event.message}`),
          }),
        (error) => {
          assert.ok(error instanceof BackupFilesystemError);
          assert.equal(error.stage, "repository-target-check");
          assert.equal(error.code, "repository-target-not-empty");
          return true;
        },
      );
      assert.ok(stages.includes("source-validation:source validated"));
      assert.ok(
        stages.includes(
          "temporary-storage-config:temporary storage config created",
        ),
      );
      assert.ok(stages.includes("repository-check:repository check started"));
      const resticCalls = await readCalls(
        path.join(fixture.dataDir, "restic-calls"),
      );
      const rcloneCalls = await readCalls(
        path.join(fixture.dataDir, "rclone.calls"),
      );
      assert.ok(rcloneCalls.some((args) => args[0] === "lsf"));
      assert.equal(
        await readFile(
          path.join(fixture.dataDir, "rclone.config-check"),
          "utf8",
        ),
        "obscured\n",
      );
      assert.ok(resticCalls.some((args) => args.includes("snapshots")));
      assert.ok(!resticCalls.some((args) => args.includes("init")));
      assert.ok(!resticCalls.some((args) => args.includes("backup")));
      assert.deepEqual(
        (await readdir(fixture.dataDir)).filter((name) =>
          name.startsWith("rclone-"),
        ),
        [],
      );
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  },
);

linuxExecutionTest(
  "initializes an empty managed target and reaches Restic backup",
  async () => {
    const fixture = await createExecutionFixture("");
    const stages: string[] = [];
    try {
      const result = await executeFilesystemBackup({
        ...executionInput(fixture),
        onStage: (event) => stages.push(`${event.stage}:${event.message}`),
      });
      assert.equal(result.snapshotId, "abcdef0123456789");
      assert.ok(stages.includes("repository-target-check:target-empty"));
      assert.ok(
        stages.includes(
          "repository-initialization:repository initialization started",
        ),
      );
      assert.ok(stages.includes("restic-backup:restic backup started"));
      assert.ok(stages.includes("restic-backup:backup completed"));
      const resticCalls = await readCalls(
        path.join(fixture.dataDir, "restic-calls"),
      );
      assert.ok(resticCalls.some((args) => args.includes("init")));
      assert.ok(resticCalls.some((args) => args.includes("backup")));
      assert.deepEqual(
        (await readdir(fixture.dataDir)).filter((name) =>
          name.startsWith("rclone-"),
        ),
        [],
      );
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  },
);

linuxExecutionTest(
  "initializes a missing managed target instead of treating exit code 3 as fatal",
  async () => {
    const fixture = await createExecutionFixture(
      "",
      3,
      "Failed to lsf: directory not found\n",
    );
    const stages: string[] = [];
    try {
      await executeFilesystemBackup({
        ...executionInput(fixture),
        onStage: (event) => stages.push(`${event.stage}:${event.message}`),
      });
      assert.ok(stages.includes("repository-target-check:target-not-found"));
      const resticCalls = await readCalls(
        path.join(fixture.dataDir, "restic-calls"),
      );
      const rcloneCalls = await readCalls(
        path.join(fixture.dataDir, "rclone.calls"),
      );
      assert.deepEqual(rcloneCalls, [
        ["lsf", "pluton:managed-repositories/example"],
      ]);
      assert.ok(
        resticCalls.some(
          (args) =>
            args.includes("init") &&
            args[1] === "rclone:pluton:managed-repositories/example",
        ),
      );
      assert.ok(resticCalls.some((args) => args.includes("backup")));
      assert.deepEqual(
        (await readdir(fixture.dataDir)).filter((name) =>
          name.startsWith("rclone-"),
        ),
        [],
      );
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  },
);

for (const scenario of [
  {
    name: "authentication",
    diagnostics:
      "ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain",
    code: "target-check-auth-failed",
  },
  {
    name: "permission",
    diagnostics: "error listing target: permission denied",
    code: "target-check-access-failed",
  },
  {
    name: "transport",
    diagnostics: "dial tcp: connection refused",
    code: "target-check-transport-failed",
  },
  {
    name: "malformed configuration",
    diagnostics: "config section not found",
    code: "repository-target-check-failed",
  },
]) {
  linuxExecutionTest(
    `refuses init on ${scenario.name} failure and cleans up credentials`,
    async () => {
      const fixtureSecret = "synthetic-provider-secret-marker";
      const fixture = await createExecutionFixture(
        "",
        1,
        `${scenario.diagnostics}: ${fixtureSecret}\n`,
      );
      const stages: string[] = [];
      try {
        await assert.rejects(
          () =>
            executeFilesystemBackup({
              ...executionInput(fixture),
              onStage: (event) =>
                stages.push(`${event.stage}:${event.message}`),
            }),
          (error) => {
            assert.ok(error instanceof BackupFilesystemError);
            assert.equal(error.stage, "repository-target-check");
            assert.equal(error.code, scenario.code);
            assert.ok(!error.message.includes(fixtureSecret));
            assert.ok(!JSON.stringify(error).includes(fixtureSecret));
            return true;
          },
        );
        const calls = await readCalls(
          path.join(fixture.dataDir, "restic-calls"),
        );
        assert.ok(
          !calls.some(
            (args) => args.includes("init") || args.includes("backup"),
          ),
        );
        assert.ok(
          !stages.some(
            (stage) =>
              stage.includes("target-empty") ||
              stage.includes("target-not-found"),
          ),
        );
        assert.ok(!JSON.stringify(stages).includes(fixtureSecret));
        assert.deepEqual(
          (await readdir(fixture.dataDir)).filter((name) =>
            name.startsWith("rclone-"),
          ),
          [],
        );
      } finally {
        await rm(fixture.root, { recursive: true, force: true });
      }
    },
  );
}

linuxExecutionTest(
  "payload v5: follows version 3 source rules without exclusions and version 4 rules with them",
  async () => {
    const fixture = await createExecutionFixture("");
    const unreadable = path.join(fixture.source, "included.txt");
    await writeFile(unreadable, "synthetic included");
    await chmod(unreadable, 0);
    try {
      const base = executionInput(fixture);
      // Without exclusions the server would have sent version 1 to 3: no pre-backup scan.
      await executeFilesystemBackup({
        ...base,
        payload: sftpVersion5Payload(fixture.source),
        commandSeal: sealContext,
      });
      // With exclusions the server would have sent version 4: scan and anchored filters.
      await assert.rejects(
        executeFilesystemBackup({
          ...base,
          payload: sftpVersion5Payload(fixture.source, ["node_modules/"]),
          commandSeal: sealContext,
        }),
        (error: unknown) =>
          error instanceof BackupFilesystemError &&
          error.stage === "source-validation" &&
          error.code === "source-entry-inaccessible",
      );
      await chmod(unreadable, 0o600);
      await executeFilesystemBackup({
        ...base,
        payload: sftpVersion5Payload(fixture.source, ["*.sql"]),
        commandSeal: sealContext,
      });
      const backups = (
        await readCalls(path.join(fixture.dataDir, "restic-calls"))
      ).filter((args) => args.includes("backup"));
      assert.equal(backups.length, 2);
      assert.ok(!backups[0].some((arg) => arg.includes("**/")));
      assert.ok(backups[1].includes(`${fixture.source}/**/*.sql`));
    } finally {
      await chmod(unreadable, 0o600);
      await rm(fixture.root, { recursive: true, force: true });
    }
  },
);

/**
 * Fake Rclone/Restic for S3 version 5 runs. The first `lsf` is the S3 access
 * check (Task 7), any later `lsf` the empty-target check. Each call records its
 * arguments and SSL_CERT_FILE; the config is copied for inspection.
 */
async function createS3ExecutionFixture(
  options: {
    accessExit?: number;
    targetListing?: string;
    targetExit?: number;
    lsfDiagnostics?: string;
    backupExit?: number;
    backupDiagnostics?: string;
  } = {},
) {
  const root = await mkdtemp(path.join(os.tmpdir(), "pluton-agent-s3-"));
  const source = path.join(root, "source");
  const dataDir = path.join(root, "state");
  const binDir = path.join(root, "bin");
  await Promise.all([mkdir(source), mkdir(dataDir), mkdir(binDir)]);
  await writeFile(path.join(source, "app.txt"), "synthetic source\n");
  await writeFile(
    path.join(binDir, "rclone"),
    `#!/usr/bin/env node
import { appendFileSync, copyFileSync, existsSync, writeFileSync } from "node:fs";
import path from "node:path";
const args = process.argv.slice(2);
const config = process.env.RCLONE_CONFIG || "";
if (!config) {
  process.exitCode = 97;
} else {
  const state = path.dirname(path.dirname(config));
  appendFileSync(path.join(state, "rclone.calls"), JSON.stringify(args) + "\\n");
  appendFileSync(path.join(state, "rclone.env"), JSON.stringify({ SSL_CERT_FILE: process.env.SSL_CERT_FILE ?? null }) + "\\n");
  if (args[0] === "lsf") {
    copyFileSync(config, path.join(state, "rclone.config-copy"));
    const access = !existsSync(path.join(state, "access-checked"));
    writeFileSync(path.join(state, "access-checked"), "1");
    process.stderr.write(${JSON.stringify(options.lsfDiagnostics ?? "")});
    if (access) process.exitCode = ${options.accessExit ?? 0};
    else {
      process.stdout.write(${JSON.stringify(options.targetListing ?? "")});
      process.exitCode = ${options.targetExit ?? 0};
    }
  }
}
`,
  );
  await writeFile(
    path.join(binDir, "restic"),
    `#!/usr/bin/env node
import { appendFileSync } from "node:fs";
import path from "node:path";
const args = process.argv.slice(2);
const state = path.dirname(path.dirname(process.env.RCLONE_CONFIG || ""));
appendFileSync(path.join(state, "restic-calls"), JSON.stringify(args) + "\\n");
appendFileSync(path.join(state, "restic.env"), JSON.stringify({ SSL_CERT_FILE: process.env.SSL_CERT_FILE ?? null, passwordOpened: process.env.RESTIC_PASSWORD === "synthetic-repository-password-01" }) + "\\n");
if (args.includes("cat") && args.includes("config")) console.log(JSON.stringify({ version: 2, id: "c".repeat(64) }));
else if (args.includes("snapshots")) process.exitCode = 10;
else if (args.includes("backup")) {
  process.stderr.write(${JSON.stringify(options.backupDiagnostics ?? "")});
  if (${options.backupExit ?? 0} !== 0) process.exitCode = ${options.backupExit ?? 0};
  else process.stdout.write(JSON.stringify({ message_type: "summary", snapshot_id: "abcdef0123456789", files_new: 0, files_changed: 0, files_unmodified: 0, dirs_new: 0, dirs_changed: 0, dirs_unmodified: 0, data_blobs: 0, tree_blobs: 0, data_added: 0, data_added_packed: 0, total_files_processed: 0, total_bytes_processed: 0, total_duration: 0 }) + "\\n");
}
`,
  );
  await Promise.all([
    chmod(path.join(binDir, "rclone"), 0o755),
    chmod(path.join(binDir, "restic"), 0o755),
  ]);
  return { root, source, dataDir, binDir };
}

function s3ExecutionInput(
  fixture: Awaited<ReturnType<typeof createS3ExecutionFixture>>,
  payload: Record<string, unknown> = {
    ...s3Version5Payload,
    sourcePath: fixture.source,
  },
  config: Partial<AgentConfig> = {},
) {
  return {
    payload,
    commandSeal: sealContext,
    config: {
      serverUrl: new URL("https://example.invalid"),
      dataDir: fixture.dataDir,
      allowedRoots: [fixture.source],
      binDir: fixture.binDir,
      allowInsecureHttp: false,
      ...config,
    },
    allowedRoots: [fixture.source],
    shouldCancel: async () => false,
    onEvent: async () => undefined,
  };
}

async function readJsonLines<T>(file: string): Promise<T[]> {
  return (await readFile(file, "utf8"))
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as T);
}

linuxExecutionTest(
  "S3: writes a private type = s3 config with the plain sealed keys, never obscures, and backs up to the bucket prefix",
  async () => {
    const fixture = await createS3ExecutionFixture();
    const stages: string[] = [];
    try {
      const result = await executeFilesystemBackup({
        ...s3ExecutionInput(fixture),
        onStage: (event) => stages.push(`${event.stage}:${event.message}`),
      });
      assert.equal(result.snapshotId, "abcdef0123456789");
      const rcloneCalls = await readCalls(
        path.join(fixture.dataDir, "rclone.calls"),
      );
      assert.ok(!rcloneCalls.some((args) => args[0] === "obscure"));
      assert.ok(
        rcloneCalls.some(
          (args) =>
            args[0] === "lsf" && args[1] === "pluton:bucket-01/pluton/app-01",
        ),
      );
      assert.ok(
        !stages.some((stage) => stage.startsWith("sftp-password-obscure:")),
      );
      assert.ok(
        stages.includes(
          "temporary-storage-config:temporary storage config created",
        ),
      );
      const config = (
        await readFile(path.join(fixture.dataDir, "rclone.config-copy"), "utf8")
      ).split("\n");
      assert.deepEqual(config.slice(0, 3), [
        "[pluton]",
        "type = s3",
        "env_auth = false",
      ]);
      for (const line of [
        "access_key_id = SYNTHETICKEY01",
        "secret_access_key = synthetic-secret-key-01",
        "endpoint = https://s3.example.internal",
        "provider = Other",
        "force_path_style = true",
        "use_accept_encoding_gzip = false",
        "no_check_bucket = true",
      ])
        assert.ok(config.includes(line), line);
      const resticCalls = await readCalls(
        path.join(fixture.dataDir, "restic-calls"),
      );
      for (const command of ["init", "backup"])
        assert.ok(
          resticCalls.some(
            (args) =>
              args.includes(command) &&
              args[1] === "rclone:pluton:bucket-01/pluton/app-01",
          ),
          command,
        );
      assert.ok(
        (
          await readJsonLines<{ passwordOpened: boolean }>(
            path.join(fixture.dataDir, "restic.env"),
          )
        ).every((entry) => entry.passwordOpened),
      );
      assert.ok(!JSON.stringify(stages).includes("synthetic-secret-key-01"));
      assert.deepEqual(
        (await readdir(fixture.dataDir)).filter((name) =>
          name.startsWith("rclone-"),
        ),
        [],
      );
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  },
);

permissionTest(
  "S3: the temporary Rclone config is private and pins env_auth off",
  async () => {
    const dataDir = await mkdtemp(
      path.join(os.tmpdir(), "pluton-agent-s3-config-"),
    );
    try {
      const temporary = await writeTemporaryRcloneConfig(
        dataDir,
        {
          endpoint: "https://s3.example.internal",
          access_key_id: "SYNTHETICKEY01",
          secret_access_key: "synthetic-secret-key-01",
          force_path_style: "true",
          use_accept_encoding_gzip: "false",
        },
        "s3",
      );
      assert.equal((await stat(temporary.directory)).mode & 0o777, 0o700);
      assert.equal((await stat(temporary.configPath)).mode & 0o777, 0o600);
      assert.equal(
        await readFile(temporary.configPath, "utf8"),
        "[pluton]\ntype = s3\nenv_auth = false\naccess_key_id = SYNTHETICKEY01\nendpoint = https://s3.example.internal\nforce_path_style = true\nsecret_access_key = synthetic-secret-key-01\nuse_accept_encoding_gzip = false\n",
      );
      await assert.rejects(
        writeTemporaryRcloneConfig(
          dataDir,
          { endpoint: "https://s3.example.internal\n[other]" },
          "s3",
        ),
        /unsafe value/,
      );
    } finally {
      await rm(dataDir, { recursive: true, force: true });
    }
  },
);

/** Root-owned, readable PEM bundle present in the Ubuntu validation image (ca-certificates). */
const rootOwnedCaBundle = "/etc/ssl/certs/ca-certificates.crt";

linuxExecutionTest(
  "S3: PLUTON_AGENT_STORAGE_CA_FILE reaches Restic and Rclone as SSL_CERT_FILE",
  async () => {
    assert.ok(
      existsSync(rootOwnedCaBundle),
      "The Ubuntu validation image provides a root-owned CA bundle.",
    );
    for (const storageCaFile of [rootOwnedCaBundle, undefined]) {
      const fixture = await createS3ExecutionFixture();
      try {
        await executeFilesystemBackup(
          s3ExecutionInput(
            fixture,
            undefined,
            storageCaFile ? { storageCaFile } : {},
          ),
        );
        for (const file of ["rclone.env", "restic.env"])
          assert.ok(
            (
              await readJsonLines<{ SSL_CERT_FILE: string | null }>(
                path.join(fixture.dataDir, file),
              )
            ).every((entry) => entry.SSL_CERT_FILE === (storageCaFile ?? null)),
            `${file} ${storageCaFile ?? "without CA"}`,
          );
      } finally {
        await rm(fixture.root, { recursive: true, force: true });
      }
    }
  },
);

linuxExecutionTest(
  "S3: a storage CA that is not root-owned refuses the backup before any storage tool runs",
  async () => {
    const fixture = await createS3ExecutionFixture();
    const unowned = path.join(fixture.root, "storage-ca.pem");
    await writeFile(unowned, "synthetic CA\n", { mode: 0o644 });
    try {
      await assert.rejects(
        executeFilesystemBackup(
          s3ExecutionInput(fixture, undefined, { storageCaFile: unowned }),
        ),
        (error: unknown) => {
          assert.ok(error instanceof BackupFilesystemError);
          assert.equal(error.stage, "temporary-storage-config");
          assert.equal(error.code, "temporary-config-failed");
          return true;
        },
      );
      assert.ok(!existsSync(path.join(fixture.dataDir, "rclone.calls")));
      assert.ok(!existsSync(path.join(fixture.dataDir, "restic-calls")));
      assert.deepEqual(
        (await readdir(fixture.dataDir)).filter((name) =>
          name.startsWith("rclone-"),
        ),
        [],
      );
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  },
);

linuxExecutionTest(
  "S3: an SFTP backup ignores the storage CA setting",
  async () => {
    const fixture = await createExecutionFixture("");
    try {
      const input = executionInput(fixture);
      const result = await executeFilesystemBackup({
        ...input,
        config: {
          ...input.config,
          storageCaFile: path.join(fixture.root, "absent-storage-ca.pem"),
        },
      });
      assert.equal(result.snapshotId, "abcdef0123456789");
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  },
);

for (const scenario of [
  {
    name: "an unknown access key",
    diagnostics:
      "operation error S3: ListObjectsV2, https response error StatusCode: 403, RequestID: 1, HostID: 2, api error InvalidAccessKeyId: The access key ID you provided does not exist in our records.",
    code: "target-check-auth-failed",
  },
  {
    name: "a wrong secret key",
    diagnostics:
      "operation error S3: ListObjectsV2, https response error StatusCode: 403, RequestID: 1, HostID: 2, api error SignatureDoesNotMatch: The request signature we calculated does not match the signature you provided.",
    code: "target-check-auth-failed",
  },
  {
    name: "a refused bucket",
    diagnostics:
      "operation error S3: ListObjectsV2, https response error StatusCode: 403, RequestID: 1, HostID: 2, api error AccessDenied: Access Denied",
    code: "target-check-access-failed",
  },
  {
    name: "an untrusted certificate",
    diagnostics:
      'Get "https://s3.example.internal/bucket-01?delimiter=%2F": tls: failed to verify certificate: x509: certificate signed by unknown authority',
    code: "target-check-transport-failed",
  },
  {
    name: "a DNS server failure",
    diagnostics:
      "lookup s3.example.internal on 192.0.2.53:53: server misbehaving",
    code: "target-check-transport-failed",
  },
  {
    name: "a throttled endpoint",
    diagnostics:
      "operation error S3: ListObjectsV2, https response error StatusCode: 503, RequestID: 1, HostID: 2, api error SlowDown: Please reduce your request rate.",
    code: "target-check-transport-failed",
  },
  {
    name: "an unrecognised provider failure",
    diagnostics: "synthetic unrecognised provider failure",
    code: "repository-check-failed",
  },
])
  linuxExecutionTest(
    `S3: the access check maps ${scenario.name} to ${scenario.code} before Restic runs`,
    async () => {
      const providerSecret = "synthetic-provider-secret-marker";
      const fixture = await createS3ExecutionFixture({
        accessExit: 1,
        lsfDiagnostics: `${scenario.diagnostics} ${providerSecret}\n`,
      });
      const stages: import("./backupFilesystem.js").BackupFilesystemStageEvent[] =
        [];
      try {
        await assert.rejects(
          executeFilesystemBackup({
            ...s3ExecutionInput(fixture),
            onStage: (event) => stages.push(event),
          }),
          (error: unknown) => {
            assert.ok(error instanceof BackupFilesystemError);
            assert.equal(error.stage, "repository-check");
            assert.equal(error.code, scenario.code);
            assert.ok(!JSON.stringify(error).includes(providerSecret));
            return true;
          },
        );
        assert.equal(
          (await readCalls(path.join(fixture.dataDir, "rclone.calls"))).filter(
            (args) => args[0] === "lsf",
          ).length,
          1,
          "One access check, no retry loop",
        );
        assert.ok(
          !existsSync(path.join(fixture.dataDir, "restic-calls")),
          "Restic must not run after a failed S3 access check.",
        );
        assert.ok(
          stages.some((event) => event.message === "real repository failure"),
        );
        for (const forbidden of [providerSecret, "synthetic-secret-key-01"])
          assert.ok(!JSON.stringify(stages).includes(forbidden));
        assert.deepEqual(
          (await readdir(fixture.dataDir)).filter((name) =>
            name.startsWith("rclone-"),
          ),
          [],
        );
      } finally {
        await rm(fixture.root, { recursive: true, force: true });
      }
    },
  );

linuxExecutionTest(
  "S3: a missing bucket (rclone exit 3) is a repository failure, never an empty target",
  async () => {
    const fixture = await createS3ExecutionFixture({
      accessExit: 3,
      lsfDiagnostics: "directory not found\n",
    });
    try {
      await assert.rejects(
        executeFilesystemBackup(s3ExecutionInput(fixture)),
        (error: unknown) =>
          error instanceof BackupFilesystemError &&
          error.stage === "repository-check" &&
          error.code === "repository-check-failed",
      );
      assert.ok(!existsSync(path.join(fixture.dataDir, "restic-calls")));
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  },
);

linuxExecutionTest(
  "S3: objects under the prefix refuse initialization; an empty listing initializes",
  async () => {
    const occupied = await createS3ExecutionFixture({
      targetListing: "config\n",
    });
    try {
      await assert.rejects(
        executeFilesystemBackup(s3ExecutionInput(occupied)),
        (error: unknown) =>
          error instanceof BackupFilesystemError &&
          error.stage === "repository-target-check" &&
          error.code === "repository-target-not-empty",
      );
      assert.ok(
        !(await readCalls(path.join(occupied.dataDir, "restic-calls"))).some(
          (args) => args.includes("init") || args.includes("backup"),
        ),
      );
    } finally {
      await rm(occupied.root, { recursive: true, force: true });
    }
    const missingBucket = await createS3ExecutionFixture({ targetExit: 3 });
    try {
      await assert.rejects(
        executeFilesystemBackup(s3ExecutionInput(missingBucket)),
        (error: unknown) =>
          error instanceof BackupFilesystemError &&
          error.stage === "repository-target-check" &&
          error.code === "repository-target-check-failed",
      );
      assert.ok(
        !(
          await readCalls(path.join(missingBucket.dataDir, "restic-calls"))
        ).some((args) => args.includes("init")),
      );
    } finally {
      await rm(missingBucket.root, { recursive: true, force: true });
    }
    const empty = await createS3ExecutionFixture();
    const stages: string[] = [];
    try {
      await executeFilesystemBackup({
        ...s3ExecutionInput(empty),
        onStage: (event) => stages.push(`${event.stage}:${event.message}`),
      });
      assert.ok(
        stages.includes("repository-check:storage access check started"),
      );
      assert.ok(stages.includes("repository-check:storage access verified"));
      assert.ok(stages.includes("repository-target-check:target-empty"));
      assert.ok(!stages.includes("repository-target-check:target-not-found"));
      assert.equal(
        (await readCalls(path.join(empty.dataDir, "rclone.calls"))).filter(
          (args) => args[0] === "lsf",
        ).length,
        2,
      );
    } finally {
      await rm(empty.root, { recursive: true, force: true });
    }
  },
);

for (const scenario of [
  {
    name: "a refused upload",
    diagnostics:
      "rclone: operation error S3: PutObject, https response error StatusCode: 403, RequestID: 1, HostID: 2, api error AccessDenied: Access Denied\nFatal: unable to save snapshot: synthetic\n",
    code: "target-check-access-failed",
  },
  {
    name: "a rejected key",
    diagnostics:
      "rclone: operation error S3: PutObject, https response error StatusCode: 403, RequestID: 1, HostID: 2, api error SignatureDoesNotMatch: The request signature we calculated does not match the signature you provided.\n",
    code: "target-check-auth-failed",
  },
  {
    name: "a provider error",
    diagnostics:
      "rclone: operation error S3: PutObject, https response error StatusCode: 500, RequestID: 1, HostID: 2, api error InternalError: We encountered an internal error.\n",
    code: "target-check-transport-failed",
  },
  {
    name: "an unclassified failure",
    diagnostics: "Fatal: unable to save snapshot: synthetic\n",
    code: "restic-backup-failed",
  },
])
  linuxExecutionTest(
    `S3: a Restic backup failure from ${scenario.name} becomes ${scenario.code}`,
    async () => {
      const fixture = await createS3ExecutionFixture({
        backupExit: 1,
        backupDiagnostics: scenario.diagnostics,
      });
      try {
        await assert.rejects(
          executeFilesystemBackup(s3ExecutionInput(fixture)),
          (error: unknown) => {
            assert.ok(error instanceof BackupFilesystemError);
            assert.equal(error.stage, "restic-backup");
            assert.equal(error.code, scenario.code);
            assert.ok(!JSON.stringify(error).includes("RequestID"));
            return true;
          },
        );
      } finally {
        await rm(fixture.root, { recursive: true, force: true });
      }
    },
  );

const SYNTHETIC_SOURCE_READ_ERRORS = [
  "error: /srv/example-app/a.txt: read /srv/example-app/a.txt: i/o timeout",
  "error: /srv/example-app/b.txt: open /srv/example-app/b.txt: connection timed out",
  "error: /srv/example-app/c.txt: read /srv/example-app/c.txt: broken pipe",
  "error: /srv/example-app/d.txt: unexpected EOF",
  "error: /srv/example-app/AccessDenied-status code: 403.txt: lstat /srv/example-app/AccessDenied-status code: 403.txt: input/output error",
  "open /srv/example-app/e.txt: connection reset by peer",
  "Lstat /srv/example-app/f.txt: no route to host",
  "cannot read /srv/example-app/g.txt: i/o timeout",
].join("\n");

for (const scenario of [
  {
    name: "only source read errors",
    diagnostics: `${SYNTHETIC_SOURCE_READ_ERRORS}\nWarning: at least one source file could not be read\n`,
    code: "restic-backup-failed",
  },
  {
    name: "a source file named like an access error",
    diagnostics:
      "error: /srv/example-app/AccessDenied-status code: 403.txt: read /srv/example-app/AccessDenied-status code: 403.txt: EOF\n",
    code: "restic-backup-failed",
  },
  {
    name: "a Rclone transport line",
    diagnostics:
      'rclone: Failed to copy: Put "https://s3.example.internal/bucket-01/data": read tcp 192.0.2.10:1->192.0.2.11:443: i/o timeout\n',
    code: "target-check-transport-failed",
  },
  {
    name: "a Restic backend Save line",
    diagnostics:
      "Save(<data/0123456789>) returned error, retrying after 1s: i/o timeout\n",
    code: "target-check-transport-failed",
  },
  {
    name: "a backend signature line",
    diagnostics:
      "Load(<data/0123456789>, 0, 0) returned error: api error SignatureDoesNotMatch: The request signature we calculated does not match.\n",
    code: "target-check-auth-failed",
  },
  {
    name: "a backend AccessDenied line",
    diagnostics:
      "Fatal: unable to open repository: api error AccessDenied: Access Denied\n",
    code: "target-check-access-failed",
  },
  {
    name: "source errors mixed with one backend transport line",
    diagnostics: `${SYNTHETIC_SOURCE_READ_ERRORS}\nrclone: Failed to copy: connection timed out\n`,
    code: "target-check-transport-failed",
  },
  {
    name: "a source file named like an auth error next to a backend timeout",
    diagnostics:
      "error: /srv/example-app/SignatureDoesNotMatch.txt: read /srv/example-app/SignatureDoesNotMatch.txt: EOF\nSave(<data/0123456789>) returned error: i/o timeout\n",
    code: "target-check-transport-failed",
  },
])
  linuxExecutionTest(
    `S3: backup stderr with ${scenario.name} reports ${scenario.code}`,
    async () => {
      const fixture = await createS3ExecutionFixture({
        backupExit: 1,
        backupDiagnostics: scenario.diagnostics,
      });
      const stages: string[] = [];
      try {
        await assert.rejects(
          executeFilesystemBackup({
            ...s3ExecutionInput(fixture),
            onStage: (event) => stages.push(`${event.stage}:${event.message}`),
          }),
          (error: unknown) => {
            assert.ok(error instanceof BackupFilesystemError);
            assert.equal(error.stage, "restic-backup");
            assert.equal(error.code, scenario.code);
            const text = JSON.stringify([error, stages]);
            for (const leaked of [
              "/srv/example-app",
              "example.internal",
              "192.0.2.",
              "bucket-01",
              "0123456789",
              "AccessDenied-status",
            ])
              assert.ok(!text.includes(leaked), leaked);
            return true;
          },
        );
      } finally {
        await rm(fixture.root, { recursive: true, force: true });
      }
    },
  );

linuxExecutionTest(
  "S3: SFTP Restic backup failures keep restic-backup-failed",
  async () => {
    const fixture = await createExecutionFixture("");
    await writeFile(
      path.join(fixture.binDir, "restic"),
      `#!/usr/bin/env node
const args = process.argv.slice(2);
if (args.includes("cat") && args.includes("config")) console.log(JSON.stringify({ version: 2, id: "c".repeat(64) }));
else if (args.includes("snapshots")) process.exitCode = 1;
else if (args.includes("backup")) { process.stderr.write("api error AccessDenied: Access Denied StatusCode: 403\\n"); process.exitCode = 1; }
`,
    );
    try {
      await assert.rejects(
        executeFilesystemBackup(executionInput(fixture)),
        (error: unknown) =>
          error instanceof BackupFilesystemError &&
          error.stage === "restic-backup" &&
          error.code === "restic-backup-failed",
      );
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  },
);
