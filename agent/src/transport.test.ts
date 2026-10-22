import assert from "node:assert/strict";
import test, { before, after } from "node:test";
import https from "node:https";
import net from "node:net";
import dns from "node:dns";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import type { Duplex } from "node:stream";
import { AgentTransport, AgentHttpError } from "./transport.js";
import { AgentNetworkError } from "./network.js";
import { createAgentConfig } from "./config.js";
import { AgentClient } from "./client.js";
import { atAgentStage, formatAgentFailure } from "./errors.js";
import { networkPreflight } from "./networkPreflight.js";

let directory: string;
let key: Buffer;
let cert: Buffer;
before(() => {
  directory = mkdtempSync(path.join(os.tmpdir(), "pluton-tls-test-"));
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1",
    "-keyout", path.join(directory, "key.pem"), "-out", path.join(directory, "cert.pem")], { stdio: "ignore" });
  key = readFileSync(path.join(directory, "key.pem"));
  cert = readFileSync(path.join(directory, "cert.pem"));
});
after(() => rmSync(directory, { recursive: true, force: true }));

const lookup = (addresses: dns.LookupAddress[]): typeof dns.lookup =>
  ((_host: string, _options: unknown, callback: (error: Error | null, result: dns.LookupAddress[]) => void) =>
    queueMicrotask(() => callback(null, addresses))) as typeof dns.lookup;
const v4 = { address: "127.0.0.1", family: 4 };
const v6 = { address: "::1", family: 6 };

async function fixture(host = "127.0.0.1", status = 200, response = '{"success":true,"result":{}}') {
  let count = 0;
  const sockets = new Set<Duplex>();
  const server = https.createServer({ key, cert }, (request, res) => {
    count++;
    request.resume();
    res.writeHead(status, { "content-type": "application/json" });
    res.end(response);
  });
  server.on("connection", (socket) => { sockets.add(socket); socket.once("close", () => sockets.delete(socket)); });
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, host, resolve); });
  const port = (server.address() as net.AddressInfo).port;
  return { server, port, count: () => count, config: createAgentConfig({
    serverUrl: `https://localhost:${port}`, caFile: path.join(directory, "cert.pem"),
  }), close: async () => { for (const socket of sockets) socket.destroy(); await new Promise<void>((resolve) => server.close(() => resolve())); } };
}

test("verified HTTPS works IPv4-only, IPv6-only, and healthy dual-stack with one POST", async () => {
  for (const [host, addresses] of [["127.0.0.1", [v4]], ["::1", [v6]], ["::", [v6, v4]]] as const) {
    const f = await fixture(host);
    try {
      await new AgentTransport(f.config, 2000, undefined, { lookup: lookup([...addresses]), staggerMs: 20 }).post("/api/agent/enroll", '{"token":"synthetic-only"}');
      assert.equal(f.count(), 1);
    } finally { await f.close(); }
  }
});

test("unreachable IPv6 falls back to IPv4 and unreachable IPv4 falls back to IPv6", async () => {
  for (const [host, addresses] of [["127.0.0.1", [v6, v4]], ["::1", [v4, v6]]] as const) {
    const f = await fixture(host);
    try {
      await new AgentTransport(f.config, 2000, undefined, { lookup: lookup([...addresses]), staggerMs: 20 }).post("/api/agent/enroll", "{}");
      assert.equal(f.count(), 1);
    } finally { await f.close(); }
  }
});

test("a stalled first-family TLS handshake cannot block the other family or duplicate credentials", async () => {
  for (const [host, stalledHost, addresses] of [["127.0.0.1", "::1", [v6, v4]], ["::1", "127.0.0.1", [v4, v6]]] as const) {
    const f = await fixture(host);
    const sockets = new Set<net.Socket>();
    let bytes = "";
    const stalled = net.createServer((socket) => {
      sockets.add(socket); socket.on("data", (data) => { bytes += data.toString(); });
    });
    await new Promise<void>((resolve, reject) => { stalled.once("error", reject); stalled.listen(f.port, stalledHost, resolve); });
    try {
      await new AgentTransport(f.config, 2000, undefined, { lookup: lookup([...addresses]), staggerMs: 25 }).post("/api/agent/enroll", '{"token":"synthetic-credential-must-not-replay"}');
      assert.equal(f.count(), 1);
      assert.ok(!bytes.includes("synthetic-credential-must-not-replay"));
    } finally { for (const socket of sockets) socket.destroy(); await new Promise<void>((resolve) => stalled.close(() => resolve())); await f.close(); }
  }
});

test("DNS failure and DNS latency have bounded safe classifications", async () => {
  const f = await fixture();
  try {
    const missing = ((_host: string, _options: unknown, callback: (error: Error) => void) =>
      callback(Object.assign(new Error("do not log synthetic secrets"), { code: "ENOTFOUND" }))) as typeof dns.lookup;
    for (const [resolver, code] of [[missing, "DNS_FAILURE"], [(() => {}) as unknown as typeof dns.lookup, "DNS_TIMEOUT"]] as const) {
      await assert.rejects(new AgentTransport(f.config, 1000, undefined, { lookup: resolver, dnsTimeoutMs: 30 }).post("/", "{}"),
        (error: unknown) => error instanceof AgentNetworkError && error.code === code);
    }
    assert.equal(f.count(), 0);
  } finally { await f.close(); }
});

test("connection/TLS handshake and entire request deadlines are independent and bounded", async () => {
  const f = await fixture();
  const held = new Set<net.Socket>();
  const stalled = net.createServer((socket) => held.add(socket));
  await new Promise<void>((resolve) => stalled.listen(0, "127.0.0.1", resolve));
  const config = { ...f.config, serverUrl: new URL(`https://localhost:${(stalled.address() as net.AddressInfo).port}`) };
  try {
    await assert.rejects(new AgentTransport(config, 1000, undefined, { lookup: lookup([v4]), attemptTimeoutMs: 30 }).post("/", "{}"), { code: "CONNECT_TIMEOUT" });
    f.server.removeAllListeners("request");
    f.server.on("request", (_request, response) => { response.writeHead(200); response.write("{"); });
    await assert.rejects(new AgentTransport(f.config, 80, undefined, { lookup: lookup([v4]) }).post("/", "{}"), { code: "REQUEST_TIMEOUT" });
  } finally { for (const socket of held) socket.destroy(); await new Promise<void>((resolve) => stalled.close(() => resolve())); await f.close(); }
});

test("certificate trust and original hostname verification fail closed before POST", async () => {
  const f = await fixture();
  try {
    for (const config of [{ ...f.config, caFile: undefined }, { ...f.config, serverUrl: new URL(`https://wrong.example.invalid:${f.port}`) }]) {
      await assert.rejects(new AgentTransport(config, 2000, undefined, { lookup: lookup([v4]) }).post("/api/agent/enroll", "{}"), { code: "TLS_VERIFICATION_FAILED" });
    }
    assert.equal(f.count(), 0);
  } finally { await f.close(); }
});

test("HTTP errors preserve bounded status classifications without leaking server responses", async () => {
  for (const status of [400, 401, 403, 429, 500]) {
    const f = await fixture("127.0.0.1", status, '{"error":"synthetic-private-token"}');
    try {
      await assert.rejects(atAgentStage("enroll", () => new AgentTransport(f.config, 2000, undefined, { lookup: lookup([v4]) }).post("/api/agent/enroll", "{}")),
        (error: unknown) => {
          assert.equal(formatAgentFailure(error), `enroll failed: server returned HTTP ${status}.`);
          assert.equal(f.count(), 1); return true;
        });
    } finally { await f.close(); }
  }
});

test("invalid JSON, oversized responses and interrupted connections fail safely without retry", async () => {
  const f = await fixture("127.0.0.1", 200, "synthetic-sensitive-invalid-json");
  try {
    await assert.rejects(new AgentTransport(f.config, 2000, undefined, { lookup: lookup([v4]) }).post("/", "{}"), { code: "INVALID_RESPONSE" });
    await assert.rejects(new AgentTransport(f.config, 2000, 4, { lookup: lookup([v4]) }).post("/", "{}"), { code: "RESPONSE_TOO_LARGE" });
    f.server.removeAllListeners("request");
    f.server.on("request", (_request, response) => { response.writeHead(200, { "content-length": 1000 }); response.write("{"); setTimeout(() => response.destroy(), 10); });
    await assert.rejects(new AgentTransport(f.config, 2000, undefined, { lookup: lookup([v4]) }).post("/", "{}"), { code: "CONNECTION_INTERRUPTED" });
  } finally { await f.close(); }
});

test("HTTPS origin fencing and explicit HTTP opt-in remain required", async () => {
  const f = await fixture();
  try {
    assert.throws(() => new AgentTransport({ ...f.config, serverUrl: new URL("http://localhost") }), { code: "REQUEST_REJECTED" });
    await assert.rejects(new AgentTransport(f.config).post("http://localhost/api/agent/enroll", "{}"), { code: "REQUEST_REJECTED" });
    assert.equal(f.count(), 0);
  } finally { await f.close(); }
});

test("application enrollment rejection and invalid envelopes never surface arbitrary error bodies", async () => {
  for (const response of ['{"success":false,"error":"synthetic-private-secret"}', 'null', '{"success":true,"result":{}}']) {
    const f = await fixture("::", 200, response);
    try {
      const client = new AgentClient(f.config);
      await assert.rejects(atAgentStage("enroll", () => client.enroll("synthetic-only-token", {} as never)), (error: unknown) => {
        const output = formatAgentFailure(error);
        assert.ok(output.includes(response.includes('"success":false') ? "enrollment rejected" : "invalid server response"));
        assert.ok(!output.includes("synthetic-private-secret"));
        assert.equal(f.count(), 1); return true;
      });
    } finally { await f.close(); }
  }
});

test("explicit network preflight sends only unauthenticated health GETs and never reads private state", async () => {
  const f = await fixture("::");
  const requests: string[] = [];
  f.server.removeAllListeners("request");
  f.server.on("request", (request, response) => {
    assert.equal(request.method, "GET"); assert.equal(request.url, "/api/health");
    assert.equal(request.headers.authorization, undefined);
    assert.equal(request.headers["x-pluton-agent-id"], undefined);
    requests.push(request.url!); response.end('{"success":true}');
  });
  try {
    assert.equal(await networkPreflight({ ...f.config, dataDir: "/unreadable/nonexistent/private-state" }), true);
    assert.equal(requests.length, 3);
    assert.equal(await networkPreflight({ ...f.config, serverUrl: new URL("http://localhost"), allowInsecureHttp: true }), false);
    assert.equal(requests.length, 3);
  } finally { await f.close(); }
});
