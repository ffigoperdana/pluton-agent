import { AgentTransport } from "./transport.js";
import { sanitizeAgentError } from "./errors.js";
import { DNS_TIMEOUT_MS, REQUEST_TIMEOUT_MS } from "./network.js";
import type { AgentConfig } from "./types.js";

/** Explicit unauthenticated GET only. No identity, token, poll or enrollment. */
export async function networkPreflight(config: AgentConfig): Promise<boolean> {
  if (config.serverUrl.protocol !== "https:") {
    console.log("network-check: HTTPS is required");
    return false;
  }
  console.log(`network-check: DNS deadline ${DNS_TIMEOUT_MS / 1000}s within ${REQUEST_TIMEOUT_MS / 1000}s total per probe; three sequential probes may take ${3 * REQUEST_TIMEOUT_MS / 1000}s.`);
  let automatic = false;
  for (const family of [undefined, 4, 6] as const) {
    const label = family === undefined ? "dual-stack" : `IPv${family}`;
    try {
      await new AgentTransport(config, undefined, undefined, { family }).health();
      console.log(`network-check ${label}: PASS DNS/TCP/verified TLS/HTTP JSON health`);
      if (family === undefined) automatic = true;
    } catch (error) {
      console.log(`network-check ${label}: ${sanitizeAgentError(error)}`);
    }
  }
  console.log("network-check: GET /api/health only; no enrollment credential or identity used. Family failures do not identify the production routing cause.");
  return automatic;
}
