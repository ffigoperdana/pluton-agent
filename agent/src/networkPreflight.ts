import { AgentTransport } from "./transport.js";
import { sanitizeAgentError } from "./errors.js";
import type { AgentConfig } from "./types.js";

/** Explicit unauthenticated GET only. No identity, token, poll or enrollment. */
export async function networkPreflight(config: AgentConfig): Promise<boolean> {
  if (config.serverUrl.protocol !== "https:") {
    console.log("network-check: HTTPS is required");
    return false;
  }
  let automatic = false;
  for (const family of [undefined, 4, 6] as const) {
    const label = family === undefined ? "dual-stack" : `IPv${family}`;
    try {
      await new AgentTransport(config, 10000, 2 * 1024 * 1024, { family }).health();
      console.log(`network-check ${label}: PASS DNS/TCP/verified TLS/HTTP JSON health`);
      if (family === undefined) automatic = true;
    } catch (error) {
      console.log(`network-check ${label}: ${sanitizeAgentError(error)}`);
    }
  }
  console.log("network-check: GET /api/health only; no enrollment credential or identity used. Family failures do not identify the production routing cause.");
  return automatic;
}
