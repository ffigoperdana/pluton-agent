import dns from "node:dns";
import net from "node:net";
import tls from "node:tls";
import type { AgentConfig } from "./types.js";

export type NetworkFailure =
  | "DNS_FAILURE" | "DNS_TIMEOUT" | "CONNECT_TIMEOUT" | "CONNECT_FAILURE"
  | "TLS_VERIFICATION_FAILED" | "CONNECTION_INTERRUPTED" | "REQUEST_TIMEOUT"
  | "INVALID_RESPONSE" | "RESPONSE_TOO_LARGE" | "ENROLLMENT_REJECTED" | "REQUEST_REJECTED";

export class AgentNetworkError extends Error {
  constructor(public readonly code: NetworkFailure) {
    super(code === "REQUEST_TIMEOUT" ? "Agent request timed out." :
      code === "RESPONSE_TOO_LARGE" ? "Agent response exceeded the safe size limit." : code);
    this.name = "AgentNetworkError";
  }
}

const tlsCodes = new Set([
  "ERR_TLS_CERT_ALTNAME_INVALID", "DEPTH_ZERO_SELF_SIGNED_CERT", "SELF_SIGNED_CERT_IN_CHAIN",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE", "UNABLE_TO_GET_ISSUER_CERT", "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "CERT_HAS_EXPIRED", "CERT_NOT_YET_VALID", "CERT_REVOKED", "ERR_TLS_CERT_SIGNATURE_ALGORITHM_UNSUPPORTED",
  "ERR_OSSL_PEM_NO_START_LINE", "ERR_OSSL_X509_KEY_VALUES_MISMATCH",
]);

export function classifyNetworkError(error: unknown): AgentNetworkError {
  if (error instanceof AgentNetworkError) return error;
  const code = (error as NodeJS.ErrnoException | undefined)?.code;
  if (code && tlsCodes.has(code)) return new AgentNetworkError("TLS_VERIFICATION_FAILED");
  if (code === "ENOTFOUND" || code === "EAI_AGAIN" || code === "EAI_FAIL") return new AgentNetworkError("DNS_FAILURE");
  if (code === "ETIMEDOUT") return new AgentNetworkError("CONNECT_TIMEOUT");
  if (code === "ECONNRESET" || code === "EPIPE" || code === "ERR_STREAM_PREMATURE_CLOSE") return new AgentNetworkError("CONNECTION_INTERRUPTED");
  return new AgentNetworkError("CONNECT_FAILURE");
}

export interface NetworkOptions {
  lookup?: typeof dns.lookup;
  staggerMs?: number;
  attemptTimeoutMs?: number;
  dnsTimeoutMs?: number;
  // Used only by the explicit read-only family diagnostic, never by enrollment.
  family?: 4 | 6;
}

export function serverHostname(url: URL): string {
  return url.hostname.replace(/^\[|\]$/g, "");
}

/** Race connection/verified TLS handshakes only. No HTTP bytes are sent here.
 * Unlike sequential autoSelectFamily, launching the next address does not
 * cancel a slow but viable earlier connection. The caller owns one winner.
 */
export async function connectServer(
  config: AgentConfig,
  tlsOptions: tls.ConnectionOptions,
  signal: AbortSignal,
  options: NetworkOptions = {},
): Promise<net.Socket> {
  const hostname = serverHostname(config.serverUrl);
  const family = net.isIP(hostname);
  const lookup = options.lookup ?? dns.lookup;
  const addresses = await new Promise<dns.LookupAddress[]>((resolve, reject) => {
    const finish = (error?: Error | null, result?: dns.LookupAddress[]) => {
      clearTimeout(timer);
      signal.removeEventListener("abort", abort);
      if (error) reject(error); else resolve(result!);
    };
    const abort = () => finish(signal.reason);
    const timer = setTimeout(() => finish(new AgentNetworkError("DNS_TIMEOUT")), options.dnsTimeoutMs ?? 3000);
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) { abort(); return; }
    if (family) { finish(null, [{ address: hostname, family }]); return; }
    try {
      lookup(hostname, { all: true, verbatim: true }, (error, result) => {
        finish(error ? new AgentNetworkError("DNS_FAILURE") : null, result);
      });
    } catch { finish(new AgentNetworkError("DNS_FAILURE")); }
  });
  if (signal.aborted) throw signal.reason;
  const unique = addresses.filter((entry, index, all) =>
    (entry.family === 4 || entry.family === 6) && (!options.family || entry.family === options.family) &&
    all.findIndex((other) => other.address === entry.address && other.family === entry.family) === index);
  if (!unique.length) throw new AgentNetworkError("DNS_FAILURE");
  // Alternate families, retaining resolver order within each family. Bound the
  // number of simultaneous sockets even for unexpectedly large DNS answers.
  const first = unique.filter((entry) => entry.family === unique[0].family);
  const second = unique.filter((entry) => entry.family !== unique[0].family);
  const ordered: dns.LookupAddress[] = [];
  while ((first.length || second.length) && ordered.length < 16) {
    if (first.length) ordered.push(first.shift()!);
    if (second.length) ordered.push(second.shift()!);
  }
  return new Promise((resolve, reject) => {
    const sockets = new Set<net.Socket>();
    const timers = new Set<ReturnType<typeof setTimeout>>();
    let settled = false;
    let completed = 0;
    let lastError: AgentNetworkError = new AgentNetworkError("CONNECT_FAILURE");
    const cleanup = (winner?: net.Socket) => {
      signal.removeEventListener("abort", abort);
      for (const timer of timers) clearTimeout(timer);
      for (const socket of sockets) if (socket !== winner) socket.destroy();
    };
    const abort = () => {
      if (settled) return;
      settled = true; cleanup(); reject(signal.reason);
    };
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) { abort(); return; }
    ordered.forEach((address, index) => {
      const start = setTimeout(() => {
        if (settled) return;
        const secure = config.serverUrl.protocol === "https:";
        const connection = { host: address.address, family: address.family,
          port: Number(config.serverUrl.port || (secure ? 443 : 80)), autoSelectFamily: false };
        let socket: net.Socket;
        try { socket = secure ? tls.connect({ ...tlsOptions, ...connection,
          servername: net.isIP(hostname) ? undefined : hostname,
          rejectUnauthorized: true,
          checkServerIdentity: (_name, certificate) => tls.checkServerIdentity(hostname, certificate),
        }) : net.createConnection(connection); }
        catch (error) {
          completed++; lastError = classifyNetworkError(error);
          if (lastError.code === "TLS_VERIFICATION_FAILED" || completed === ordered.length) {
            settled = true; cleanup(); reject(lastError);
          }
          return;
        }
        sockets.add(socket);
        let done = false;
        const failed = (error: unknown) => {
          if (done || settled) return;
          done = true; clearTimeout(timeout); socket.destroy(); completed++;
          lastError = classifyNetworkError(error);
          // Certificate errors are terminal: never work around a trust failure
          // by picking a different address or relaxing verification.
          if (lastError.code === "TLS_VERIFICATION_FAILED" || completed === ordered.length) {
            settled = true; cleanup(); reject(lastError);
          }
        };
        const timeout = setTimeout(() => failed(new AgentNetworkError("CONNECT_TIMEOUT")), options.attemptTimeoutMs ?? 5000);
        timers.add(timeout);
        socket.once("error", failed);
        socket.once(secure ? "secureConnect" : "connect", () => {
          if (done || settled) return;
          done = true; settled = true; cleanup(socket);
          // Keep a listener until the HTTP client takes ownership next turn.
          resolve(socket);
        });
      }, index * (options.staggerMs ?? 250));
      timers.add(start);
    });
  });
}
