import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { runOnce } from "./runtime.js";
import { saveIdentity } from "./identity.js";
import type { AgentCommandEnvelope, StoredAgentIdentity } from "./types.js";

const tools = process.env.PLUTON_PHASE5_TEST_TOOLS;
/** Same boundary as lifecycleTransport.test.ts: unprivileged Linux with root-owned private tools. */
const executionTest =
  process.platform === "linux" && tools && process.getuid?.() !== 0
    ? test
    : test.skip;
const LABEL = "pluton-agent-command-secrets-v1";
const identity: StoredAgentIdentity = {
  deviceId: "device-01",
  agentId: "agent-01",
  secret: "synthetic-agent-secret-0123456789abcdef",
  pollIntervalSeconds: 1,
  completedCommands: [],
};
const repositoryPassword = "synthetic-repository-password-01";
const sftpPassword = "synthetic-sftp-password-01";

/** Independent test sealer; the Agent itself only opens. */
function seal(commandId: string, leaseToken: string, plaintext: unknown) {
  const key = Buffer.from(
    crypto.hkdfSync(
      "sha256",
      Buffer.from(identity.secret, "utf8"),
      Buffer.alloc(0),
      Buffer.from(LABEL, "utf8"),
      32,
    ),
  );
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce, {
    authTagLength: 16,
  });
  cipher.setAAD(Buffer.from(`${LABEL}\n${commandId}\n${leaseToken}`, "utf8"));
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(plaintext), "utf8"),
    cipher.final(),
  ]);
  return {
    alg: "A256GCM",
    kid: LABEL,
    nonce: nonce.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
  };
}

function leasedCommand(
  id: string,
  payloadFor: (leaseToken: string) => Record<string, unknown>,
): AgentCommandEnvelope {
  const leaseToken = crypto.randomBytes(24).toString("hex");
  const command: AgentCommandEnvelope = {
    id,
    type: "BACKUP_FILESYSTEM",
    idempotencyKey: `backup:${id}`,
    leaseToken,
    leaseExpiresAt: new Date(Date.now() + 60_000).toISOString(),
    signatureTimestamp: String(Date.now()),
    signature: "",
    payload: payloadFor(leaseToken),
  };
  command.signature = crypto
    .createHmac("sha256", identity.secret)
    .update(
      [
        "command",
        command.signatureTimestamp,
        command.id,
        command.type,
        JSON.stringify(command.payload),
        command.idempotencyKey,
        command.leaseToken,
        Date.parse(command.leaseExpiresAt!).toString(),
      ].join("\n"),
    )
    .digest("base64");
  return command;
}

function sftpPayload(source: string, sealed: unknown): Record<string, unknown> {
  return {
    version: 5,
    planId: "plan-01",
    backupId: "backup-01",
    sourcePath: source,
    excludes: [],
    repository: {
      remoteName: "pluton",
      path: "managed/app-01",
      initialize: true,
    },
    rclone: {
      type: "sftp",
      options: { host: "sftp.example.internal", user: "backup_reader" },
    },
    sealed,
  };
}

async function runLeasedBackup(
  commandFor: (source: string) => AgentCommandEnvelope,
) {
  const scratch = await mkdtemp(
    path.join(os.tmpdir(), "pluton-sealed-runtime-"),
  );
  const source = path.join(scratch, "source");
  const dataDir = path.join(scratch, "state");
  await mkdir(source);
  await mkdir(dataDir, { mode: 0o700 });
  await writeFile(path.join(source, "app.txt"), "synthetic app");
  await saveIdentity(dataDir, { ...identity, completedCommands: [] });
  const command = commandFor(source);
  const completions: Record<string, unknown>[] = [];
  const output: unknown[] = [];
  const server = http.createServer(async (request, response) => {
    let raw = "";
    for await (const chunk of request) raw += chunk.toString();
    const body = JSON.parse(raw);
    let result: unknown = {};
    if (request.url === "/api/agent/poll") result = { command };
    else if (request.url?.endsWith("/status")) result = { cancelled: false };
    else if (request.url?.endsWith("/complete")) completions.push(body);
    response.writeHead(200, { "content-type": "application/json" });
    response.end(
      JSON.stringify(
        request.url === "/api/agent/heartbeat" ||
          request.url === "/api/agent/poll" ||
          request.url?.endsWith("/status")
          ? { success: true, result }
          : { success: true },
      ),
    );
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const previousInfo = console.info,
    previousError = console.error;
  console.info = (...args) => {
    output.push(args);
  };
  console.error = (...args) => {
    output.push(args);
  };
  try {
    await runOnce({
      serverUrl: new URL(
        `http://127.0.0.1:${(server.address() as { port: number }).port}`,
      ),
      dataDir,
      allowedRoots: [source],
      allowInsecureHttp: true,
      binDir: path.join(tools!, "bin"),
      databaseBinDirs: [path.join(tools!, "bin")],
    });
  } finally {
    console.info = previousInfo;
    console.error = previousError;
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
  return { scratch, dataDir, completions, output };
}

executionTest(
  "sealed runtime: a v5 command sealed to another command or lease is refused before any backup file is written",
  async () => {
    for (const misbinding of ["command", "lease"] as const) {
      const run = await runLeasedBackup((source) =>
        leasedCommand("command-sealed-01", (leaseToken) =>
          sftpPayload(
            source,
            seal(
              misbinding === "command"
                ? "command-sealed-other"
                : "command-sealed-01",
              misbinding === "lease"
                ? crypto.randomBytes(24).toString("hex")
                : leaseToken,
              { repositoryPassword, rclone: { pass: sftpPassword } },
            ),
          ),
        ),
      );
      try {
        assert.equal(run.completions.length, 1, misbinding);
        assert.equal(run.completions[0].success, false);
        assert.equal(run.completions[0].failureStage, "payload-validation");
        assert.equal(run.completions[0].failureCode, "invalid-payload");
        const files = await readdir(run.dataDir);
        assert.ok(
          !files.some(
            (name) =>
              name.startsWith("rclone-") ||
              name === "jobs" ||
              name === "restic-cache" ||
              name === "restic-calls",
          ),
          files.join(","),
        );
        for (const forbidden of [
          repositoryPassword,
          sftpPassword,
          identity.secret,
        ])
          assert.ok(
            !JSON.stringify([run.completions, run.output]).includes(forbidden),
          );
      } finally {
        await rm(run.scratch, { recursive: true, force: true });
      }
    }
  },
);

executionTest(
  "sealed runtime: a v5 SFTP command opens its secrets with the per-Agent secret, command ID and lease token",
  async () => {
    const run = await runLeasedBackup((source) =>
      leasedCommand("command-sealed-02", (leaseToken) =>
        sftpPayload(
          source,
          seal("command-sealed-02", leaseToken, {
            repositoryPassword,
            rclone: { pass: sftpPassword },
          }),
        ),
      ),
    );
    try {
      assert.equal(run.completions.length, 1);
      assert.equal(
        run.completions[0].success,
        true,
        JSON.stringify({
          stage: run.completions[0].failureStage,
          code: run.completions[0].failureCode,
        }),
      );
      const calls = (
        await readFile(path.join(run.dataDir, "restic-calls"), "utf8")
      )
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line) as string[]);
      assert.ok(
        calls.some(
          (args) =>
            args.includes("backup") &&
            args[1] === "rclone:pluton:managed/app-01",
        ),
      );
      for (const forbidden of [
        repositoryPassword,
        sftpPassword,
        identity.secret,
      ])
        assert.ok(
          !JSON.stringify([run.completions, run.output]).includes(forbidden),
        );
    } finally {
      await rm(run.scratch, { recursive: true, force: true });
    }
  },
);
