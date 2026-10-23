import assert from "node:assert/strict";
import test from "node:test";
import http from "node:http";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { AgentClient } from "./client.js";
import { createAgentConfig } from "./config.js";
import { collectInventory } from "./inventory.js";
import { signRequest } from "./protocol.js";
import { saveIdentity } from "./identity.js";
import { runOnce } from "./runtime.js";
import type { AgentCommandEnvelope } from "./types.js";

const identity = { agentId: "agent-01", deviceId: "app-01", secret: "synthetic-contract-secret", pollIntervalSeconds: 5, completedCommands: [] };
const lease = "a".repeat(32);
const inventory = collectInventory({ filesystemRootsConfigured: false });
async function fixture(t: test.TestContext) {
  let body = '{"success":true}', status = 200;
  const requests: { url: string; body: Record<string, unknown> }[] = [];
  const nonces = new Set<string>();
  const server = http.createServer(async (req, res) => {
    let raw = "";
    for await (const chunk of req) raw += chunk;
    if (req.url !== "/api/agent/enroll") {
      const nonce = String(req.headers["x-pluton-agent-nonce"]);
      assert.ok(!nonces.has(nonce)); nonces.add(nonce);
      assert.equal(req.headers["x-pluton-agent-id"], identity.agentId);
      assert.equal(req.headers["x-pluton-agent-signature"], signRequest(identity.secret,
        String(req.headers["x-pluton-agent-timestamp"]), nonce, "POST", req.url!, raw));
    }
    requests.push({ url: req.url!, body: JSON.parse(raw) });
    res.writeHead(status, { "content-type": "application/json" }); res.end(body);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise<void>((resolve) => server.close(() => resolve())));
  const config = createAgentConfig({ serverUrl: "http://127.0.0.1:" + (server.address() as import("node:net").AddressInfo).port, allowInsecureHttp: true });
  return { config, requests, client: new AgentClient(config, identity), reply: (value: unknown, code = 200) => { body = JSON.stringify(value); status = code; }, raw: (value: string, code = 200) => { body = value; status = code; } };
}

test("server void ACK/events/complete success does not require result, with signed lease unchanged", async (t) => {
  const f = await fixture(t);
  await f.client.acknowledge("command-01", lease);
  await f.client.event("command-01", lease, 1, { phase: "accepted" });
  await f.client.complete("command-01", lease, { sequence: 2, success: true });
  assert.equal(f.requests.length, 3);
  assert.ok(f.requests.every((r) => r.body.leaseToken === lease));
});

test("void endpoints reject invalid envelopes, malformed bodies, unsupported status and redirects without replay or leaks", async (t) => {
  const f = await fixture(t);
  for (const value of [{}, { success: false, error: identity.secret }, { success: null }, { success: "true" }, null, [], true, 1, "private"]) {
    f.reply(value);
    await assert.rejects(f.client.acknowledge("command-01", lease), (error: Error) => { assert.ok(!error.message.includes(identity.secret)); return true; });
  }
  for (const body of ["", "{", "<html>synthetic-private-body</html>"]) {
    f.raw(body);
    await assert.rejects(f.client.acknowledge("command-01", lease), { code: "INVALID_RESPONSE" });
  }
  for (const status of [204, 301, 302, 307, 400, 401, 403, 409, 429, 500]) {
    f.reply({ success: true }, status);
    await assert.rejects(f.client.acknowledge("command-01", lease));
  }
  assert.equal(f.requests.length, 22);
  for (const invoke of [() => f.client.event("command-01", lease, 1), () => f.client.complete("command-01", lease, { sequence: 2, success: true })]) {
    f.reply({ success: false }); await assert.rejects(invoke(), { code: "REQUEST_REJECTED" });
  }
});

test("required results remain strict for enrollment, heartbeat, poll and status", async (t) => {
  const f = await fixture(t);
  for (const invoke of [() => f.client.enroll("synthetic-token", inventory), () => f.client.heartbeat(inventory), () => f.client.poll(), () => f.client.commandStatus("command-01", lease)]) {
    for (const value of [{ success: true }, { success: true, result: null }, { success: true, result: [] }, { success: true, result: "private" }]) {
      f.reply(value); await assert.rejects(invoke(), { code: "INVALID_RESPONSE" });
    }
  }
  for (const result of [{}, { command: false }, { command: 0 }, { command: {} }, { command: { id: "command-01" } }]) {
    f.reply({ success: true, result }); await assert.rejects(f.client.poll(), { code: "INVALID_RESPONSE" });
  }
  for (const result of [{}, { cancelled: "false" }, { cancelled: null }]) {
    f.reply({ success: true, result }); await assert.rejects(f.client.commandStatus("command-01", lease), { code: "INVALID_RESPONSE" });
  }
  for (const field of ["agentId", "deviceId", "secret", "pollIntervalSeconds"]) {
    const result: Record<string, unknown> = { ...identity }; delete result[field];
    f.reply({ success: true, result }); await assert.rejects(f.client.enroll("synthetic-token", inventory), { code: "INVALID_RESPONSE" });
  }
  f.reply({ success: true, result: identity }, 201); assert.equal((await f.client.enroll("synthetic-token", inventory)).agentId, identity.agentId);
  f.reply({ success: true, result: {} }); await f.client.heartbeat(inventory);
  f.reply({ success: true, result: { command: null } }); assert.equal(await f.client.poll(), null);
  for (const cancelled of [false, true]) { f.reply({ success: true, result: { cancelled } }); assert.deepEqual(await f.client.commandStatus("command-01", lease), { cancelled }); }
});

function command(leaseToken = lease): AgentCommandEnvelope {
  const c: AgentCommandEnvelope = { id: "command-01", type: "PING", payload: {}, idempotencyKey: "ping:01", leaseToken, leaseExpiresAt: new Date(Date.now() + 60000).toISOString(), signatureTimestamp: String(Date.now()), signature: "" };
  c.signature = crypto.createHmac("sha256", identity.secret).update(["command", c.signatureTimestamp, c.id, c.type, JSON.stringify(c.payload), c.idempotencyKey, c.leaseToken, Date.parse(c.leaseExpiresAt!).toString()].join("\n")).digest("base64");
  return c;
}

test("poll keeps signature and lease expiry checks before ACK", async (t) => {
  const f = await fixture(t);
  const valid = command(); f.reply({ success: true, result: { command: valid } }); assert.deepEqual(await f.client.poll(), valid);
  for (const c of [{ ...valid, signature: "invalid" }, { ...valid, leaseExpiresAt: new Date(0).toISOString() }, { ...valid, leaseToken: "b".repeat(32) }]) {
    f.reply({ success: true, result: { command: c } }); await assert.rejects(f.client.poll());
  }
  assert.ok(f.requests.every((r) => r.url === "/api/agent/poll"));
});

const linux = process.platform === "linux" && process.getuid?.() !== 0 ? test : test.skip;
linux("accepted but ambiguous ACK never executes; re-lease and completion receipt survive restart without duplicate execution", async (t) => {
  const f = await fixture(t);
  const dataDir = await mkdtemp(path.join(os.tmpdir(), "agent-ack-contract-"));
  t.after(() => rm(dataDir, { recursive: true, force: true }));
  await saveIdentity(dataDir, { ...identity, completedCommands: [] });
  const config = { ...f.config, dataDir, sourcePolicyFile: path.join(dataDir, "absent-host-policy") };
  // Scripted server lease responses: models accepted ACK, occupied lease, then re-lease.
  const c = command(), reissued = command("b".repeat(32));
  const serverReplies: [unknown, string][] = [
    [{ success: true, result: {} }, "heartbeat"], [{ success: true, result: { command: c } }, "poll"], [{ success: "true" }, "ack"],
    [{ success: true, result: {} }, "heartbeat"], [{ success: true, result: { command: null } }, "poll"],
    [{ success: true, result: {} }, "heartbeat"], [{ success: true, result: { command: reissued } }, "poll"], [{ success: true }, "ack"], [{ success: true }, "events"], [{ success: "true" }, "complete"],
    [{ success: true, result: {} }, "heartbeat"], [{ success: true, result: { command: reissued } }, "poll"], [{ success: true }, "complete"],
  ];
  // Separate response script uses the real transport/client/runtime; no core execution mock.
  const server = http.createServer(async (req, res) => {
    let raw = ""; for await (const chunk of req) raw += chunk;
    const next = serverReplies.shift()!; assert.ok(req.url!.endsWith(next[1]));
    f.requests.push({ url: req.url!, body: JSON.parse(raw) }); res.end(JSON.stringify(next[0]));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise<void>((resolve) => server.close(() => resolve())));
  config.serverUrl = new URL("http://127.0.0.1:" + (server.address() as import("node:net").AddressInfo).port);
  await assert.rejects(runOnce(config));
  assert.equal(f.requests.filter((r) => r.url.endsWith("/events")).length, 0);
  await runOnce(config); // non-expired occupied lease offers no work
  await assert.rejects(runOnce(config)); // completed locally, ambiguous completion response
  const before = await readFile(path.join(dataDir, "identity.json"), "utf8");
  assert.equal(JSON.parse(before).completedCommands.length, 1);
  await runOnce(config); // new client + durable receipt: completion only, no ACK/event/execution
  assert.equal(f.requests.filter((r) => r.url.endsWith("/events")).length, 1);
  assert.equal(f.requests.filter((r) => r.url.endsWith("/ack")).length, 2);
  assert.equal(f.requests.filter((r) => r.url.endsWith("/complete")).length, 2);
  assert.equal(await readFile(path.join(dataDir, "identity.json"), "utf8"), before);
  assert.equal(f.requests.filter((r) => r.url.endsWith("/ack"))[1].body.leaseToken, reissued.leaseToken);
  assert.equal(serverReplies.length, 0);
});
