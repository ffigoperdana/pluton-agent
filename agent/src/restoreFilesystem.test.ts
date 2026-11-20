import assert from "node:assert/strict";
import crypto from "node:crypto";
import * as fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  RestoreFilesystemError,
  addListingLine,
  executeFilesystemRestore,
  parseRestoreFilesystemPayload,
  restoreProgressFromRestic,
  restoreProgressStage,
  selectedBy,
  spaceSufficient,
  validateSnapshotSelectionPath,
  type RestoreSizing,
} from "./restoreFilesystem.js";
import { SealedSecretsError } from "./sealedSecrets.js";
import type { RestorePolicyIO } from "./restorePolicy.js";
import type { AgentConfig } from "./types.js";

/** The real Agent runs on Linux; shebang fixtures and ownership checks are not portable. */
const linuxExecutionTest = process.platform === "win32" ? test.skip : test;

const sealContext = {
  secret: "synthetic-agent-secret-0123456789abcdef",
  commandId: "agent-restore-0123456789abcdef01234567",
  leaseToken: "0123456789abcdef0123456789abcdef0123456789abcdef",
};
const SEAL_LABEL = "pluton-agent-command-secrets-v1";
const REPOSITORY_PASSWORD = "synthetic-repository-password-01";
const SFTP_PASSWORD = "synthetic-sftp-password-01";
const SNAPSHOT = "a1".repeat(32);

/** Independent test sealer (node:crypto only); the Agent itself only opens. */
function sealForTest(plaintext: unknown, context = sealContext) {
  const key = Buffer.from(
    crypto.hkdfSync(
      "sha256",
      Buffer.from(context.secret, "utf8"),
      Buffer.alloc(0),
      Buffer.from(SEAL_LABEL, "utf8"),
      32,
    ),
  );
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce, {
    authTagLength: 16,
  });
  cipher.setAAD(
    Buffer.from(`${SEAL_LABEL}\n${context.commandId}\n${context.leaseToken}`, "utf8"),
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

const sftpSecrets = {
  repositoryPassword: REPOSITORY_PASSWORD,
  rclone: { pass: SFTP_PASSWORD },
};

function payload(
  root = "/srv/pluton-restore",
  overrides: Record<string, unknown> = {},
  secrets: unknown = sftpSecrets,
): Record<string, unknown> {
  return {
    version: 1,
    restoreId: "0123456789abcdef01234567",
    planId: "plan-01",
    backupId: "backup-01",
    snapshotId: SNAPSHOT,
    target: { root, name: "app-01-20261120-01234567" },
    selection: { includes: [], excludes: [] },
    repository: { remoteName: "pluton", path: "managed/app-01" },
    rclone: {
      type: "sftp",
      options: { host: "sftp.example.internal", port: "22", user: "backup-user" },
    },
    sealed: sealForTest(secrets),
    ...overrides,
  };
}

test("restore payload version 1 opens sealed SFTP and S3 secrets", () => {
  const parsed = parseRestoreFilesystemPayload(payload(), sealContext);
  assert.equal(parsed.repositoryPassword, REPOSITORY_PASSWORD);
  assert.equal(parsed.rclone.options.pass, SFTP_PASSWORD);
  assert.deepEqual(parsed.selection, { includes: [], excludes: [] });
  const s3 = parseRestoreFilesystemPayload(
    payload(
      "/srv/pluton-restore",
      {
        repository: { remoteName: "pluton", path: "bucket-01/managed/app-01" },
        rclone: {
          type: "s3",
          options: {
            provider: "Other",
            endpoint: "https://s3.example.internal",
            force_path_style: "true",
            use_accept_encoding_gzip: "false",
          },
        },
      },
      {
        repositoryPassword: REPOSITORY_PASSWORD,
        rclone: { access_key_id: "SYNTHETICKEY01", secret_access_key: "synthetic-secret-key-01" },
      },
    ),
    sealContext,
  );
  assert.equal(s3.rclone.options.secret_access_key, "synthetic-secret-key-01");
  const artifact = parseRestoreFilesystemPayload(
    payload("/srv/pluton-restore", {
      selection: { includes: ["/pluton/database/odoo.sql"], excludes: [] },
      artifact: { path: "/pluton/database/odoo.sql", bytes: 12, sha256: "b".repeat(64) },
    }),
    sealContext,
  );
  assert.equal(artifact.artifact?.bytes, 12);
});

test("restore payload refuses unknown fields, plain secrets and unsafe targets or selections", () => {
  const refusals: [Record<string, unknown>, RegExp | (new () => Error)][] = [
    [{ ...payload(), extra: true }, /unsupported fields/],
    [{ ...payload(), repositoryPassword: REPOSITORY_PASSWORD }, /unsupported fields/],
    [{ ...payload(), version: 2 }, /version is unsupported/],
    [{ ...payload(), restoreId: "short" }, /Restore ID/],
    [{ ...payload(), snapshotId: "a1b2c3d4" }, /full Restic ID/],
    [{ ...payload(), planId: "plan/01" }, /Plan ID/],
    [{ ...payload(), target: { root: "/srv/pluton-restore", name: "../escape" } }, /target is invalid/],
    [{ ...payload(), target: { root: "/srv/pluton-restore", name: "a/b" } }, /target is invalid/],
    [{ ...payload(), target: { root: "/srv/pluton-restore", name: ".hidden" } }, /target is invalid/],
    [{ ...payload(), target: { root: "/srv/pluton-restore", name: "app.partial" } }, /target is invalid/],
    [{ ...payload(), target: { root: "/srv/pluton-restore", name: "x".repeat(101) } }, /target is invalid/],
    [{ ...payload(), target: { root: "/srv/pluton-restore", name: "ok", extra: 1 } }, /unsupported fields/],
    [{ ...payload(), selection: { includes: ["relative"], excludes: [] } }, /selection path/],
    [{ ...payload(), selection: { includes: ["/srv/a*"], excludes: [] } }, /selection path/],
    [{ ...payload(), selection: { includes: ["/srv/a/../b"], excludes: [] } }, /selection path/],
    [{ ...payload(), selection: { includes: ["/srv/a/"], excludes: [] } }, /selection path/],
    [{ ...payload(), selection: { includes: ["/"], excludes: [] } }, /selection path/],
    [{ ...payload(), selection: { includes: ["/srv/a", "/srv/a"], excludes: [] } }, /repeats/],
    [{ ...payload(), selection: { includes: ["/srv/a", "/srv/a/b"], excludes: [] } }, /overlaps itself/],
    [{ ...payload(), selection: { includes: ["/srv/a"], excludes: ["/srv/a/b"] } }, /cannot combine/],
    [{ ...payload(), selection: { includes: [] } }, /unsupported fields/],
    [
      {
        ...payload(),
        selection: { includes: ["/srv/other.sql"], excludes: [] },
        artifact: { path: "/pluton/database/odoo.sql", bytes: 1, sha256: "b".repeat(64) },
      },
      /artifact is invalid/,
    ],
    [
      {
        ...payload(),
        selection: { includes: ["/pluton/database/odoo.txt"], excludes: [] },
        artifact: { path: "/pluton/database/odoo.txt", bytes: 1, sha256: "b".repeat(64) },
      },
      /artifact is invalid/,
    ],
    [{ ...payload(), rclone: { type: "local", options: {} } }, /unsupported/],
    [
      {
        ...payload(),
        rclone: { type: "sftp", options: { host: "sftp.example.internal", user: "u", pass: "plain" } },
      },
      /must be sealed/,
    ],
    [{ ...payload(), repository: { remoteName: "other", path: "x" } }, /Repository configuration/],
    [{ ...payload(), repository: { remoteName: "pluton", path: "../x" } }, /traversal/],
    [payload("/srv/pluton-restore", {}, { ...sftpSecrets, lifecycle: { database: "x" } }), SealedSecretsError],
    [payload("/srv/pluton-restore", {}, { repositoryPassword: REPOSITORY_PASSWORD, rclone: {} }), SealedSecretsError],
    [
      payload("/srv/pluton-restore", {}, {
        repositoryPassword: REPOSITORY_PASSWORD,
        rclone: { pass: SFTP_PASSWORD, access_key_id: "K" },
      }),
      SealedSecretsError,
    ],
  ];
  for (const [value, expected] of refusals)
    assert.throws(() => parseRestoreFilesystemPayload(value, sealContext), expected as RegExp, JSON.stringify(value).slice(0, 160));
  // Bound to the leased command: another lease token or command cannot open it.
  assert.throws(
    () => parseRestoreFilesystemPayload(payload(), { ...sealContext, leaseToken: "f".repeat(48) }),
    SealedSecretsError,
  );
  assert.throws(
    () => parseRestoreFilesystemPayload(payload(), { ...sealContext, commandId: "agent-restore-other" }),
    SealedSecretsError,
  );
  assert.throws(() => parseRestoreFilesystemPayload(payload(), undefined), /leased command context/);
});

test("selection, listing and space rules use exact path semantics", () => {
  assert.equal(validateSnapshotSelectionPath("/srv/example-app/filestore"), "/srv/example-app/filestore");
  assert.equal(selectedBy({ includes: ["/srv/a"], excludes: [] }, "/srv/a/b"), true);
  assert.equal(selectedBy({ includes: ["/srv/a"], excludes: [] }, "/srv/ab"), false);
  assert.equal(selectedBy({ includes: [], excludes: ["/srv/a"] }, "/srv/a/b"), false);
  assert.equal(selectedBy({ includes: [], excludes: ["/srv/a"] }, "/srv/ab"), true);
  const sizing: RestoreSizing = { bytes: 0, entries: 0, files: 0, found: new Set() };
  const selection = { includes: ["/srv/a"], excludes: [] };
  for (const line of [
    JSON.stringify({ struct_type: "snapshot", id: SNAPSHOT }),
    JSON.stringify({ message_type: "node", type: "dir", path: "/srv/a" }),
    JSON.stringify({ message_type: "node", type: "file", path: "/srv/a/x", size: 10 }),
    JSON.stringify({ struct_type: "node", type: "file", path: "/srv/ab", size: 99 }),
    JSON.stringify({ struct_type: "node", type: "symlink", path: "/srv/a/link" }),
    "not json",
    "",
  ])
    addListingLine(sizing, selection, line);
  assert.deepEqual(
    { bytes: sizing.bytes, entries: sizing.entries, files: sizing.files, found: [...sizing.found] },
    { bytes: 10, entries: 3, files: 1, found: ["/srv/a"] },
  );
  const GiB = 1024 ** 3;
  assert.equal(spaceSufficient({ bytes: 10 * GiB, entries: 10 }, { bytes: 11 * GiB, inodes: 2000 }), true);
  assert.equal(spaceSufficient({ bytes: 10 * GiB, entries: 10 }, { bytes: 10.9 * GiB }), false);
  assert.equal(spaceSufficient({ bytes: 100 * GiB, entries: 10 }, { bytes: 104 * GiB }), false, "5 % reserve");
  assert.equal(spaceSufficient({ bytes: 1, entries: 400_000 }, { bytes: 10 * GiB, inodes: 400_500 }), false, "inodes");
  assert.equal(spaceSufficient({ bytes: 1, entries: 400_000 }, { bytes: 10 * GiB }), true, "no inode accounting");
  assert.deepEqual(
    restoreProgressFromRestic({
      message_type: "status",
      total_files: 4,
      files_restored: 2,
      total_bytes: 40,
      bytes_restored: 20,
    }),
    {
      phase: "running",
      restoreStage: "restoring",
      progress: { bytesProcessed: 20, filesProcessed: 2, totalBytesProcessed: 40, totalFilesProcessed: 4 },
    },
  );
  assert.equal(restoreProgressFromRestic({ message_type: "summary" }), null);
  assert.equal(restoreProgressStage("space-check"), "checking-space");
  assert.equal(restoreProgressStage("restic-restore"), "restoring");
  assert.equal(restoreProgressStage("payload-validation"), "preparing-restore");
});

type FixtureFile = { path: string; content: string };
type Mode = {
  files: FixtureFile[];
  snapshots: unknown;
  restore?: "ok" | "fail" | "hang";
  corrupt?: string;
};

const FILES: FixtureFile[] = [
  { path: "/srv/example-app/filestore/ab/0001", content: "attachment-one" },
  { path: "/srv/example-app/filestore/cd/0002", content: "attachment-two" },
  { path: "/srv/example-app/config/app.conf", content: "synthetic=true" },
  { path: "/pluton/database/odoo.sql", content: "-- synthetic dump\nSELECT 1;\n" },
];

const RESTIC = `#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
const mode = JSON.parse(fs.readFileSync(path.join(__dirname, "mode.json"), "utf8"));
const args = process.argv.slice(2);
fs.appendFileSync(path.join(__dirname, "restic.calls"), JSON.stringify(args) + "\\n");
if (!process.env.RESTIC_PASSWORD || !process.env.RCLONE_CONFIG) process.exit(9);
const sub = args.find((a) => ["cat", "snapshots", "ls", "restore"].includes(a));
const files = mode.files;
const within = (p, filters) => filters.some((f) => p === f || p.startsWith(f + "/"));
const dirs = new Set();
for (const f of files) {
  let p = path.posix.dirname(f.path);
  while (p !== "/") { dirs.add(p); p = path.posix.dirname(p); }
}
if (sub === "cat") { console.log(JSON.stringify({ version: 2, id: "c".repeat(64) })); process.exit(0); }
if (sub === "snapshots") { console.log(JSON.stringify(mode.snapshots)); process.exit(0); }
if (sub === "ls") {
  const rest = args.slice(args.indexOf("ls") + 1).filter((a) => !a.startsWith("--"));
  const filters = rest.slice(1);
  const show = (p) => !filters.length || within(p, filters);
  console.log(JSON.stringify({ struct_type: "snapshot", message_type: "snapshot", id: rest[0] }));
  for (const d of [...dirs].sort()) if (show(d)) console.log(JSON.stringify({ name: path.posix.basename(d), type: "dir", path: d, struct_type: "node", message_type: "node" }));
  for (const f of files) if (show(f.path)) console.log(JSON.stringify({ name: path.posix.basename(f.path), type: "file", path: f.path, size: Buffer.byteLength(f.content), struct_type: "node", message_type: "node" }));
  process.exit(0);
}
if (sub === "restore") {
  const target = args[args.indexOf("--target") + 1];
  const pick = (flag) => args.flatMap((a, i) => (a === flag ? [args[i + 1]] : []));
  const includes = pick("--include"), excludes = pick("--exclude");
  const selected = files.filter((f) => (!includes.length || within(f.path, includes)) && !within(f.path, excludes));
  let n = 0, bytes = 0;
  for (const f of selected) {
    const out = path.join(target, f.path.slice(1));
    fs.mkdirSync(path.dirname(out), { recursive: true });
    fs.writeFileSync(out, mode.corrupt === f.path ? "corrupted" : f.content);
    n++; bytes += Buffer.byteLength(f.content);
    console.log(JSON.stringify({ message_type: "status", total_files: selected.length, files_restored: n, total_bytes: 0, bytes_restored: bytes }));
    if (mode.restore === "fail") { process.stderr.write("Fatal: There were 1 errors\\n"); process.exit(1); }
  }
  if (mode.restore === "hang") { setInterval(() => {}, 1000); return; }
  console.log(JSON.stringify({ message_type: "summary", total_files: selected.length, files_restored: n, total_bytes: bytes, bytes_restored: bytes }));
  process.exit(0);
}
process.exit(2);
`;

const RCLONE = `#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
const args = process.argv.slice(2);
fs.appendFileSync(path.join(__dirname, "rclone.calls"), JSON.stringify(args) + "\\n");
if (args[0] === "obscure") {
  let input = "";
  process.stdin.on("data", (c) => (input += c));
  process.stdin.on("end", () => process.stdout.write("obscured-test-value\\n"));
} else if (args[0] === "lsf") process.exit(0);
else process.exit(2);
`;

async function fixture(mode: Partial<Mode> = {}) {
  // Restore roots below /tmp are refused by policy, so the fixture lives in HOME.
  const base = await fs.mkdtemp(
    path.join(process.env.PLUTON_RESTORE_TEST_HOME || os.homedir(), ".pluton-restore-test-"),
  );
  const root = path.join(base, "restore-root");
  const dataDir = path.join(base, "state");
  const binDir = path.join(base, "bin");
  const etc = path.join(base, "etc");
  await Promise.all([
    fs.mkdir(root, { mode: 0o700 }),
    fs.mkdir(dataDir, { mode: 0o700 }),
    fs.mkdir(binDir),
    fs.mkdir(etc, { mode: 0o755 }),
  ]);
  await fs.chmod(root, 0o700);
  await fs.writeFile(path.join(binDir, "restic"), RESTIC, { mode: 0o755 });
  await fs.writeFile(path.join(binDir, "rclone"), RCLONE, { mode: 0o755 });
  await fs.symlink(process.execPath, path.join(binDir, "node"));
  const fullMode: Mode = {
    files: FILES,
    snapshots: [{ id: SNAPSHOT, tags: ["pluton-plan-plan-01", "pluton-backup-backup-01"] }],
    restore: "ok",
    ...mode,
  };
  await fs.writeFile(path.join(binDir, "mode.json"), JSON.stringify(fullMode));
  const uid = process.getuid!();
  const policyFile = path.join(etc, "restore-roots.json");
  const agentId = "agent-synthetic-0123456789";
  await fs.writeFile(
    policyFile,
    JSON.stringify({ version: 1, agentId, hostVersion: 1, roots: [root] }),
    { mode: 0o644 },
  );
  await fs.chmod(policyFile, 0o644);
  const config: AgentConfig = {
    serverUrl: new URL("https://pluton.example.internal"),
    dataDir,
    allowedRoots: ["/srv/example-app"],
    binDir,
    allowInsecureHttp: false,
    restorePolicyFile: policyFile,
  };
  // Production requires root-owned ancestors and policy. In this unprivileged
  // fixture only those paths are presented as administrator-owned (the test
  // user) and not group/other-writable; the restore root itself is real.
  const real = fs as unknown as RestorePolicyIO;
  const io: RestorePolicyIO = {
    ...real,
    lstat: async (name: string) => {
      const info = await fs.lstat(name);
      if (name === root || name.startsWith(`${root}/`)) return info;
      return Object.assign(Object.create(Object.getPrototypeOf(info)), info, {
        uid,
        mode: info.mode & ~0o022,
      });
    },
  };
  const read = async (file: string) =>
    (await fs.readFile(path.join(binDir, file), "utf8").catch(() => ""))
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line) as string[]);
  return {
    base,
    root,
    dataDir,
    binDir,
    config,
    agentId,
    io,
    calls: () => read("restic.calls"),
    rcloneCalls: () => read("rclone.calls"),
    input: (
      body: Record<string, unknown>,
      extra: Partial<Parameters<typeof executeFilesystemRestore>[0]> = {},
    ): Parameters<typeof executeFilesystemRestore>[0] => ({
      payload: body,
      commandSeal: sealContext,
      config,
      agentId,
      sourceRoots: ["/srv/example-app"],
      shouldCancel: async () => false,
      onProgress: () => undefined,
      policy: { io, uid, adminUid: uid, platform: "linux" },
      trustToolDirectory: true,
      ...extra,
    }),
    cleanup: () => fs.rm(base, { recursive: true, force: true }),
  };
}

async function assertRefused(
  promise: Promise<unknown>,
  stage: string,
  code: string,
): Promise<void> {
  await assert.rejects(promise, (error: unknown) => {
    assert.ok(error instanceof RestoreFilesystemError, String(error));
    assert.equal(`${error.stage}/${error.code}`, `${stage}/${code}`);
    return true;
  });
}

async function noSecretsLeft(f: Awaited<ReturnType<typeof fixture>>) {
  const recorded = JSON.stringify([await f.calls(), await f.rcloneCalls()]);
  for (const secret of [REPOSITORY_PASSWORD, SFTP_PASSWORD])
    assert.equal(recorded.includes(secret), false, "secrets never appear in arguments");
  const leftovers = (await fs.readdir(f.dataDir)).filter((name) => name.startsWith("rclone-"));
  assert.deepEqual(leftovers, [], "the temporary storage config is removed");
}

linuxExecutionTest("whole snapshot restore lands in a new verified folder and is renamed last", async () => {
  const f = await fixture();
  try {
    const stages: string[] = [];
    const result = await executeFilesystemRestore(
      f.input(payload(f.root), { onStage: (stage) => stages.push(stage) }),
    );
    const final = path.join(f.root, "app-01-20261120-01234567");
    assert.deepEqual(result, {
      restoreId: "0123456789abcdef01234567",
      restoredSnapshotId: SNAPSHOT,
      targetPath: final,
      totalFiles: 4,
      filesRestored: 4,
      totalBytes: FILES.reduce((sum, file) => sum + Buffer.byteLength(file.content), 0),
      bytesRestored: FILES.reduce((sum, file) => sum + Buffer.byteLength(file.content), 0),
      verified: true,
    });
    assert.equal(
      await fs.readFile(path.join(final, "srv/example-app/filestore/ab/0001"), "utf8"),
      "attachment-one",
    );
    await assert.rejects(fs.lstat(`${final}.partial`), { code: "ENOENT" });
    assert.equal((await fs.lstat(final)).mode & 0o777, 0o700);
    const restore = (await f.calls()).find((args) => args.includes("restore"))!;
    assert.deepEqual(restore.slice(2), [
      "restore",
      SNAPSHOT,
      "--target",
      `${final}.partial`,
      "--overwrite",
      "never",
      "--verify",
      "--json",
    ]);
    assert.equal(restore.includes("--delete"), false);
    assert.equal(restore.includes("--no-lock"), false);
    assert.deepEqual(stages.filter((stage, i) => stages.indexOf(stage) === i), [
      "payload-validation",
      "restore-policy",
      "target-creation",
      "tool-validation",
      "sftp-password-obscure",
      "temporary-storage-config",
      "repository-check",
      "snapshot-validation",
      "space-check",
      "restic-restore",
      "finalize",
      "cleanup",
    ]);
    await noSecretsLeft(f);
  } finally {
    await f.cleanup();
  }
});

linuxExecutionTest("a selected subtree restores only the selection; excludes restore the rest", async () => {
  const f = await fixture();
  try {
    await executeFilesystemRestore(
      f.input(payload(f.root, { selection: { includes: ["/srv/example-app/filestore"], excludes: [] } })),
    );
    const final = path.join(f.root, "app-01-20261120-01234567");
    assert.equal(
      await fs.readFile(path.join(final, "srv/example-app/filestore/cd/0002"), "utf8"),
      "attachment-two",
    );
    await assert.rejects(fs.lstat(path.join(final, "srv/example-app/config")), { code: "ENOENT" });
    const calls = await f.calls();
    assert.deepEqual(
      calls.find((args) => args.includes("ls"))!.slice(2),
      ["ls", "--json", "--recursive", SNAPSHOT, "/srv/example-app/filestore"],
    );
    assert.deepEqual(
      calls.find((args) => args.includes("restore"))!.slice(-2),
      ["--include", "/srv/example-app/filestore"],
    );
    await executeFilesystemRestore(
      f.input(
        payload(f.root, {
          target: { root: f.root, name: "without-dumps" },
          selection: { includes: [], excludes: ["/pluton"] },
        }),
      ),
    );
    await assert.rejects(fs.lstat(path.join(f.root, "without-dumps/pluton")), { code: "ENOENT" });
  } finally {
    await f.cleanup();
  }
});

linuxExecutionTest("an existing target or partial folder is refused and left untouched", async () => {
  const f = await fixture();
  try {
    for (const name of ["app-01-20261120-01234567", "app-01-20261120-01234567.partial"]) {
      await fs.mkdir(path.join(f.root, name), { mode: 0o700 });
      await fs.writeFile(path.join(f.root, name, "keep.txt"), "operator data");
      await assertRefused(
        executeFilesystemRestore(f.input(payload(f.root))),
        "target-creation",
        "restore-target-exists",
      );
      assert.equal(await fs.readFile(path.join(f.root, name, "keep.txt"), "utf8"), "operator data");
      assert.deepEqual(await fs.readdir(path.join(f.root, name)), ["keep.txt"]);
      await fs.rm(path.join(f.root, name), { recursive: true });
    }
    assert.equal((await f.calls()).length, 0, "no repository work before the target check");
  } finally {
    await f.cleanup();
  }
});

linuxExecutionTest("policy, overlap and snapshot binding refuse before any folder is created", async () => {
  const f = await fixture({
    snapshots: [{ id: SNAPSHOT, tags: ["pluton-plan-plan-02", "pluton-backup-backup-01"] }],
  });
  try {
    await assertRefused(
      executeFilesystemRestore(f.input(payload(f.root))),
      "snapshot-validation",
      "restore-snapshot-mismatch",
    );
    await assertRefused(
      executeFilesystemRestore(f.input(payload(path.join(f.base, "unlisted")))),
      "restore-policy",
      "restore-root-not-approved",
    );
    await assertRefused(
      executeFilesystemRestore({ ...f.input(payload(f.root)), sourceRoots: [f.base] }),
      "restore-policy",
      "restore-root-overlap",
    );
    await fs.chmod(f.root, 0o750);
    await assertRefused(
      executeFilesystemRestore(f.input(payload(f.root))),
      "restore-policy",
      "restore-root-unsafe",
    );
    await fs.chmod(f.root, 0o700);
    assert.deepEqual(await fs.readdir(f.root), [], "nothing was created");
    await noSecretsLeft(f);
  } finally {
    await f.cleanup();
  }
});

linuxExecutionTest("a missing selection or too little space refuses without a folder", async () => {
  const f = await fixture();
  try {
    await assertRefused(
      executeFilesystemRestore(
        f.input(payload(f.root, { selection: { includes: ["/srv/example-app/missing"], excludes: [] } })),
      ),
      "space-check",
      "restore-selection-missing",
    );
    const tight: RestorePolicyIO = {
      ...f.io,
      statfs: async (name: string) => ({ ...(await fs.statfs(name)), bavail: 1 }),
    };
    await assertRefused(
      executeFilesystemRestore({
        ...f.input(payload(f.root)),
        policy: { io: tight, uid: process.getuid!(), adminUid: process.getuid!(), platform: "linux" },
      }),
      "space-check",
      "restore-insufficient-space",
    );
    assert.deepEqual(await fs.readdir(f.root), []);
    assert.equal((await f.calls()).some((args) => args.includes("restore")), false);
  } finally {
    await f.cleanup();
  }
});

linuxExecutionTest("a Restic failure keeps the partial folder for review and never renames it", async () => {
  const f = await fixture({ restore: "fail" });
  try {
    await assertRefused(
      executeFilesystemRestore(f.input(payload(f.root))),
      "restic-restore",
      "restic-restore-failed",
    );
    const partial = path.join(f.root, "app-01-20261120-01234567.partial");
    assert.ok((await fs.lstat(partial)).isDirectory());
    await assert.rejects(fs.lstat(path.join(f.root, "app-01-20261120-01234567")), { code: "ENOENT" });
    await noSecretsLeft(f);
  } finally {
    await f.cleanup();
  }
});

linuxExecutionTest("cancellation at a stage boundary stops before the folder; during Restic it kills the run", async () => {
  const f = await fixture({ restore: "hang" });
  try {
    let checks = 0;
    await assertRefused(
      executeFilesystemRestore({
        ...f.input(payload(f.root)),
        shouldCancel: async () => ++checks > 3,
      }),
      "space-check",
      "cancelled",
    );
    assert.deepEqual(await fs.readdir(f.root), []);
    let cancel = false;
    const started = Date.now();
    const running = executeFilesystemRestore({
      ...f.input(payload(f.root)),
      shouldCancelDuringRestore: async () => cancel,
      onProgress: () => {
        cancel = true;
      },
    });
    await assertRefused(running, "restic-restore", "cancelled");
    assert.ok(Date.now() - started < 60_000);
    assert.ok((await fs.lstat(path.join(f.root, "app-01-20261120-01234567.partial"))).isDirectory());
    await noSecretsLeft(f);
  } finally {
    await f.cleanup();
  }
});

linuxExecutionTest("a database artifact restore verifies size and SHA-256 against the receipt", async () => {
  const dump = FILES[3];
  const sha256 = crypto.createHash("sha256").update(dump.content).digest("hex");
  const artifact = (name: string, hash = sha256) =>
    payload(undefined, {
      target: { root: "", name },
      selection: { includes: [dump.path], excludes: [] },
      artifact: { path: dump.path, bytes: Buffer.byteLength(dump.content), sha256: hash },
    });
  const f = await fixture();
  try {
    const good = artifact("dump-ok");
    (good.target as { root: string }).root = f.root;
    const result = await executeFilesystemRestore(f.input(good));
    assert.equal(result.artifactSha256, sha256);
    assert.equal(
      await fs.readFile(path.join(f.root, "dump-ok/pluton/database/odoo.sql"), "utf8"),
      dump.content,
    );
    const wrong = artifact("dump-wrong", "0".repeat(64));
    (wrong.target as { root: string }).root = f.root;
    await assertRefused(
      executeFilesystemRestore(f.input(wrong)),
      "artifact-verification",
      "restore-verification-failed",
    );
    assert.ok((await fs.lstat(path.join(f.root, "dump-wrong.partial"))).isDirectory());
  } finally {
    await f.cleanup();
  }
  const corrupted = await fixture({ corrupt: dump.path });
  try {
    const body = artifact("dump-corrupt");
    (body.target as { root: string }).root = corrupted.root;
    await assertRefused(
      executeFilesystemRestore(corrupted.input(body)),
      "artifact-verification",
      "restore-verification-failed",
    );
  } finally {
    await corrupted.cleanup();
  }
});

linuxExecutionTest("an S3 restore checks access with Rclone and keeps credentials out of arguments", async () => {
  const f = await fixture();
  try {
    await executeFilesystemRestore(
      f.input(
        payload(
          f.root,
          {
            repository: { remoteName: "pluton", path: "bucket-01/managed/app-01" },
            rclone: {
              type: "s3",
              options: {
                provider: "Other",
                endpoint: "https://s3.example.internal",
                force_path_style: "true",
                use_accept_encoding_gzip: "false",
              },
            },
          },
          {
            repositoryPassword: REPOSITORY_PASSWORD,
            rclone: { access_key_id: "SYNTHETICKEY01", secret_access_key: "synthetic-secret-key-01" },
          },
        ),
      ),
    );
    const rclone = await f.rcloneCalls();
    assert.deepEqual(rclone, [["lsf", "pluton:bucket-01/managed/app-01"]]);
    assert.equal(JSON.stringify(await f.calls()).includes("synthetic-secret-key-01"), false);
    await noSecretsLeft(f);
  } finally {
    await f.cleanup();
  }
});

test("a restore receipt never becomes a backup parent candidate", async () => {
  const { successfulSnapshotIds } = await import("./resticParent.js");
  assert.deepEqual(
    successfulSnapshotIds([
      {
        success: true,
        result: {
          restoreId: "0123456789abcdef01234567",
          restoredSnapshotId: SNAPSHOT,
          targetPath: "/srv/pluton-restore/app-01",
          verified: true,
        },
      },
    ]),
    [],
  );
});
