import assert from "node:assert/strict";
import test from "node:test";
import http from "node:http";
import net from "node:net";
import { spawn } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, stat, symlink } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { lockEnrollment, saveEnrollmentIdentity } from "./identity.js";
import type { StoredAgentIdentity } from "./types.js";

const identity: StoredAgentIdentity = { agentId: "synthetic-agent", deviceId: "synthetic-device",
  secret: "synthetic-private-secret", pollIntervalSeconds: 15, completedCommands: [] };

function cli(server: string, dataDir: string) {
  return new Promise<{ code: number | null; output: string }>((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(import.meta.dirname, "index.js"), "enroll",
      "--server", server, "--allow-insecure-http", "--data-dir", dataDir, "--token-stdin"],
    { stdio: ["pipe", "pipe", "pipe"] });
    let output = "";
    child.stdout.on("data", (data) => { output += data; });
    child.stderr.on("data", (data) => { output += data; });
    child.once("error", reject); child.once("close", (code) => resolve({ code, output }));
    child.stdin.on("error", () => {});
    child.stdin.end("synthetic-enrollment-token\n");
  });
}

test("CLI enrollment creates one private identity and refuses reenrollment before another POST", async () => {
  const scratch = await mkdtemp(path.join(os.tmpdir(), "pluton-enrollment-state-"));
  let requests = 0;
  const server = http.createServer((request, response) => {
    requests++; request.resume(); response.end(JSON.stringify({ success: true, result: identity }));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const origin = `http://127.0.0.1:${(server.address() as net.AddressInfo).port}`;
    const dataDir = path.join(scratch, "state");
    const first = await cli(origin, dataDir);
    assert.equal(first.code, 0, first.output);
    const original = await readFile(path.join(dataDir, "identity.json"));
    const second = await cli(origin, dataDir);
    assert.equal(second.code, 1);
    assert.ok(second.output.includes("existing identity or enrollment state requires operator review"));
    assert.deepEqual(await readFile(path.join(dataDir, "identity.json")), original);
    assert.equal(requests, 1);
    assert.equal((await stat(path.join(dataDir, "identity.json"))).mode & 0o777, 0o600);
    assert.ok(!first.output.includes(identity.secret) && !second.output.includes("synthetic-enrollment-token"));
  } finally { server.closeAllConnections(); await new Promise<void>((resolve) => server.close(() => resolve())); await rm(scratch, { recursive: true, force: true }); }
});

test("enrollment locking and exclusive persistence preserve existing or linked identities", async () => {
  const scratch = await mkdtemp(path.join(os.tmpdir(), "pluton-enrollment-lock-"));
  try {
    const dataDir = path.join(scratch, "state");
    const release = await lockEnrollment(dataDir);
    await assert.rejects(lockEnrollment(dataDir), /operator review/);
    await saveEnrollmentIdentity(dataDir, identity);
    await release();
    const original = await readFile(path.join(dataDir, "identity.json"));
    await assert.rejects(saveEnrollmentIdentity(dataDir, { ...identity, secret: "replacement-must-not-write" }), /operator review/);
    assert.deepEqual(await readFile(path.join(dataDir, "identity.json")), original);
    const linked = path.join(scratch, "linked"); await mkdir(linked, { mode: 0o700 });
    await symlink(path.join(dataDir, "identity.json"), path.join(linked, "identity.json"));
    await assert.rejects(lockEnrollment(linked), /operator review/);
    await assert.rejects(saveEnrollmentIdentity(linked, identity), /operator review/);
    assert.deepEqual(await readFile(path.join(dataDir, "identity.json")), original);
  } finally { await rm(scratch, { recursive: true, force: true }); }
});

test("a server that consumes enrollment then drops the response is contacted once and not retried", async () => {
  const scratch = await mkdtemp(path.join(os.tmpdir(), "pluton-ambiguous-enrollment-"));
  let requests = 0;
  const server = http.createServer((request, response) => {
    requests++; request.resume(); request.once("end", () => response.destroy());
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const dataDir = path.join(scratch, "state");
    const result = await cli(`http://127.0.0.1:${(server.address() as net.AddressInfo).port}`, dataDir);
    assert.equal(result.code, 1);
    assert.equal(requests, 1);
    assert.ok(result.output.includes("connection interrupted"));
    assert.ok(!result.output.includes("synthetic-enrollment-token"));
    await assert.rejects(readFile(path.join(dataDir, "identity.json")), { code: "ENOENT" });
  } finally { server.closeAllConnections(); await new Promise<void>((resolve) => server.close(() => resolve())); await rm(scratch, { recursive: true, force: true }); }
});
