import http from "node:http";
import https from "node:https";
import type tls from "node:tls";
import { readFileSync } from "node:fs";
import { AgentNetworkError, classifyNetworkError, connectServer, serverHostname, REQUEST_TIMEOUT_MS, type NetworkOptions } from "./network.js";
import type { AgentConfig } from "./types.js";

export class AgentHttpError extends Error {
  constructor(
    public readonly statusCode: number,
    message: string,
  ) {
    super(message);
  }
}

/** Outbound-only JSON transport. It starts no listener and supports future mTLS material. */
export class AgentTransport {
  private readonly client: typeof http | typeof https;
  private readonly tls: tls.ConnectionOptions;

  constructor(
    private readonly config: AgentConfig,
    private readonly timeoutMs = REQUEST_TIMEOUT_MS,
    private readonly maxResponseBytes = 2 * 1024 * 1024,
    private readonly network: NetworkOptions = {},
  ) {
    if (config.serverUrl.protocol !== "https:" &&
        !(config.serverUrl.protocol === "http:" && config.allowInsecureHttp)) {
      throw new AgentNetworkError("REQUEST_REJECTED");
    }
    this.client = config.serverUrl.protocol === "https:" ? https : http;
    this.tls =
      config.serverUrl.protocol === "https:"
        ? {
            ca: config.caFile ? readFileSync(config.caFile) : undefined,
            cert: config.clientCertFile
              ? readFileSync(config.clientCertFile)
              : undefined,
            key: config.clientKeyFile
              ? readFileSync(config.clientKeyFile)
              : undefined,
            rejectUnauthorized: true,
          }
        : {};
  }

  async post<T>(
    pathname: string,
    body: string,
    headers: Record<string, string> = {},
    timeoutMs?: number,
  ): Promise<T> {
    return this.request<T>("POST", pathname, body, headers, timeoutMs);
  }

  async health(): Promise<unknown> {
    return this.request("GET", "/api/health", "", {});
  }

  private async request<T>(method: "GET" | "POST", pathname: string, body: string,
    headers: Record<string, string>, timeoutMs = this.timeoutMs): Promise<T> {
    const url = new URL(pathname, this.config.serverUrl);
    if (url.origin !== this.config.serverUrl.origin || url.username || url.password || url.hash) {
      throw new AgentNetworkError("REQUEST_REJECTED");
    }
    const controller = new AbortController();
    // Status retries may shorten, never extend, the standalone request budget.
    // The same abort signal covers DNS, verified connection and response reads.
    const deadline = setTimeout(() => controller.abort(new AgentNetworkError("REQUEST_TIMEOUT")),
      Math.max(1, Math.min(this.timeoutMs, timeoutMs)));
    let socket: Awaited<ReturnType<typeof connectServer>> | undefined;
    const agent = this.client === https ? new https.Agent({ keepAlive: false }) : new http.Agent({ keepAlive: false });
    try {
      socket = await connectServer(this.config, this.tls, controller.signal, this.network);
      // A private single-use Agent hands one already connected, TLS-verified
      // socket to Node's HTTP client. No credentials reached losing candidates.
      agent.createConnection = () => socket!;
      const response = await new Promise<{ statusCode: number; body: string }>(
      (resolve, reject) => {
        const abort = (error: Error) => {
          reject(error);
          request.destroy();
        };
        const request = this.client.request(
          {
            protocol: url.protocol,
            hostname: serverHostname(url),
            port: url.port || undefined,
            path: `${url.pathname}${url.search}`,
            method,
            agent,
            headers: {
              "content-type": "application/json",
              "content-length": Buffer.byteLength(body).toString(),
              ...headers,
            },
          },
          (res) => {
            let raw = "";
            let received = 0;
            res.setEncoding("utf8");
            res.on("data", (chunk) => {
              received += Buffer.byteLength(chunk);
              if (received > this.maxResponseBytes)
                abort(new AgentNetworkError("RESPONSE_TOO_LARGE"));
              else raw += chunk;
            });
            res.once("error", () => abort(new AgentNetworkError("CONNECTION_INTERRUPTED")));
            res.once("aborted", () =>
              abort(new AgentNetworkError("CONNECTION_INTERRUPTED")),
            );
            res.on("end", () => {
              resolve({ statusCode: res.statusCode || 0, body: raw });
            });
          },
        );
        const aborted = () => abort(controller.signal.reason);
        controller.signal.addEventListener("abort", aborted, { once: true });
        request.once("close", () => controller.signal.removeEventListener("abort", aborted));
        request.once("error", (error) => reject(classifyNetworkError(error)));
        if (controller.signal.aborted) { aborted(); return; }
        request.end(body);
      },
    );
      if (response.statusCode < 200 || response.statusCode >= 300) {
      throw new AgentHttpError(
        response.statusCode,
        "Server rejected the agent request.",
      );
      }
      try { return JSON.parse(response.body) as T; }
      catch { throw new AgentNetworkError("INVALID_RESPONSE"); }
    } finally {
      clearTimeout(deadline);
      socket?.destroy();
      agent.destroy();
    }
  }
}
