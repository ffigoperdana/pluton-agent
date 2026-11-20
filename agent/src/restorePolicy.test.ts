import assert from "node:assert/strict";
import test from "node:test";
import { constants } from "node:fs";
import type { Stats, StatsFs } from "node:fs";
import {
  RestorePolicyError,
  approvedRestoreRoot,
  changeRestoreRoots,
  inspectRestoreRoot,
  knownSourceRoots,
  parseRestorePolicy,
  readRestorePolicy,
  restoreAccessReport,
  restoreRootLexicallyAllowed,
  type RestorePolicyContext,
  type RestorePolicyIO,
} from "./restorePolicy.js";
import type { AgentConfig } from "./types.js";

const AGENT_ID = "agent-synthetic-0123456789";
const AGENT_UID = 997;
const POLICY = "/etc/pluton-agent/restore-roots.json";

type Node = {
  type: "dir" | "file" | "link";
  uid: number;
  mode: number;
  nlink?: number;
  content?: string;
  target?: string;
  writable?: boolean;
};

function stats(node: Node, ino: number): Stats {
  const typeBits =
    node.type === "dir" ? 0o040000 : node.type === "link" ? 0o120000 : 0o100000;
  return {
    dev: 1,
    ino,
    uid: node.uid,
    gid: node.uid,
    mode: typeBits | node.mode,
    nlink: node.nlink ?? 1,
    size: node.content?.length ?? 0,
    mtimeMs: 1,
    isDirectory: () => node.type === "dir",
    isFile: () => node.type === "file",
    isSymbolicLink: () => node.type === "link",
  } as unknown as Stats;
}

function enoent(): NodeJS.ErrnoException {
  return Object.assign(new Error("ENOENT"), { code: "ENOENT" });
}

/** In-memory Linux tree: every path, its owner, mode and type. */
function fakeFs(initial: Record<string, Node>) {
  const nodes = new Map(Object.entries(initial));
  const inodes = new Map<string, number>();
  let next = 10;
  const inode = (name: string) => {
    if (!inodes.has(name)) inodes.set(name, next++);
    return inodes.get(name)!;
  };
  const io: RestorePolicyIO = {
    lstat: async (name) => {
      const node = nodes.get(name);
      if (!node) throw enoent();
      return stats(node, inode(name));
    },
    realpath: async (name) => {
      const node = nodes.get(name);
      if (!node) throw enoent();
      return node.type === "link" ? node.target! : name;
    },
    access: async (name, mode) => {
      const node = nodes.get(name);
      if (!node) throw enoent();
      if (mode & constants.W_OK && node.writable === false)
        throw Object.assign(new Error("EROFS"), { code: "EROFS" });
    },
    statfs: async () =>
      ({ bsize: 4096, bavail: 1_000_000, blocks: 2_000_000, bfree: 1_000_000, files: 500_000, ffree: 400_000, type: 0 }) as StatsFs,
    open: async (name, flags) => {
      const writing = typeof flags === "number" && (flags & constants.O_CREAT) !== 0;
      if (writing) {
        if (nodes.has(name)) throw Object.assign(new Error("EEXIST"), { code: "EEXIST" });
        nodes.set(name, { type: "file", uid: 0, mode: 0o644, content: "" });
      } else if (!nodes.has(name)) throw enoent();
      return {
        readFile: async () => nodes.get(name)!.content || "",
        writeFile: async (data: string) => {
          nodes.get(name)!.content = data;
        },
        stat: async () => stats(nodes.get(name)!, inode(name)),
        sync: async () => undefined,
        close: async () => undefined,
        chmod: async (mode: number) => {
          nodes.get(name)!.mode = mode;
        },
      };
    },
    mkdir: async (name, options) => {
      if (nodes.has(name)) throw Object.assign(new Error("EEXIST"), { code: "EEXIST" });
      nodes.set(name, { type: "dir", uid: 0, mode: options.mode });
    },
    chmod: async (name, mode) => {
      nodes.get(name)!.mode = mode;
    },
    rename: async (from, to) => {
      const node = nodes.get(from);
      if (!node) throw enoent();
      nodes.delete(from);
      inodes.delete(to);
      nodes.set(to, node);
    },
    unlink: async (name) => {
      if (!nodes.delete(name)) throw enoent();
    },
  };
  return { io, nodes };
}

const rootDir = (mode = 0o755): Node => ({ type: "dir", uid: 0, mode });

function baseTree(policy?: unknown, overrides: Record<string, Node> = {}) {
  return {
    "/": rootDir(),
    "/etc": rootDir(),
    "/etc/pluton-agent": rootDir(),
    "/srv": rootDir(),
    "/srv/pluton-restore": { type: "dir", uid: AGENT_UID, mode: 0o700 },
    "/var": rootDir(),
    "/var/lib": rootDir(),
    "/var/lib/pluton-agent": { type: "dir", uid: AGENT_UID, mode: 0o700 },
    ...(policy !== undefined
      ? { [POLICY]: { type: "file", uid: 0, mode: 0o644, content: JSON.stringify(policy) } as Node }
      : {}),
    ...overrides,
  } as Record<string, Node>;
}

const config = {
  serverUrl: new URL("https://pluton.example.internal"),
  dataDir: "/var/lib/pluton-agent",
  allowedRoots: ["/srv/example-app"],
  allowInsecureHttp: false,
} as AgentConfig;

function context(
  io: RestorePolicyIO,
  extra: Partial<RestorePolicyContext> = {},
): RestorePolicyContext {
  return {
    config,
    agentId: AGENT_ID,
    uid: AGENT_UID,
    adminUid: 0,
    sourceRoots: ["/srv/example-app"],
    platform: "linux",
    io,
    ...extra,
  };
}

const policy = (roots: string[], extra: Record<string, unknown> = {}) => ({
  version: 1,
  agentId: AGENT_ID,
  hostVersion: 1,
  roots,
  ...extra,
});

test("restore policy parser accepts only the exact bound shape", () => {
  assert.deepEqual(parseRestorePolicy(policy(["/srv/b", "/srv/a"]), AGENT_ID), {
    version: 1,
    agentId: AGENT_ID,
    hostVersion: 1,
    roots: ["/srv/a", "/srv/b"],
  });
  const refusals: [unknown, string][] = [
    [policy(["/srv/a"], { extra: true }), "restore-policy-invalid"],
    [{ ...policy(["/srv/a"]), version: 2 }, "restore-policy-invalid"],
    [{ ...policy(["/srv/a"]), hostVersion: 0 }, "restore-policy-invalid"],
    [{ ...policy(["/srv/a"]), agentId: "agent-other" }, "restore-policy-agent-mismatch"],
    [policy(["/srv/a", "/srv/a/b"]), "restore-policy-invalid"],
    [policy(["/srv/a", "/srv/a"]), "restore-policy-invalid"],
    [policy(["srv/a"]), "restore-policy-invalid"],
    [policy(["/srv/a/"]), "restore-policy-invalid"],
    [policy(["/srv/../etc"]), "restore-policy-invalid"],
    [policy(Array.from({ length: 9 }, (_, i) => `/srv/r${i}`)), "restore-policy-invalid"],
    [[], "restore-policy-invalid"],
    [null, "restore-policy-invalid"],
  ];
  for (const [value, code] of refusals)
    assert.throws(
      () => parseRestorePolicy(value, AGENT_ID),
      (error: unknown) => error instanceof RestorePolicyError && error.code === code,
      JSON.stringify(value),
    );
});

test("a missing policy approves nothing and a protected one is read", async () => {
  assert.equal(await readRestorePolicy(context(fakeFs(baseTree()).io)), undefined);
  const { io } = fakeFs(baseTree(policy(["/srv/pluton-restore"])));
  assert.deepEqual((await readRestorePolicy(context(io)))?.roots, ["/srv/pluton-restore"]);
  await assert.rejects(
    readRestorePolicy(context(io, { platform: "win32" })),
    /restore-policy-linux-required/,
  );
});

test("the policy file and every ancestor must be root-owned and immutable to others", async () => {
  const body = JSON.stringify(policy(["/srv/pluton-restore"]));
  const unsafe: Record<string, Node>[] = [
    { [POLICY]: { type: "file", uid: AGENT_UID, mode: 0o644, content: body } },
    { [POLICY]: { type: "file", uid: 0, mode: 0o664, content: body } },
    { [POLICY]: { type: "file", uid: 0, mode: 0o644, nlink: 2, content: body } },
    { [POLICY]: { type: "link", uid: 0, mode: 0o777, target: "/tmp/x" } },
    { "/etc/pluton-agent": { type: "dir", uid: AGENT_UID, mode: 0o755 } },
    { "/etc/pluton-agent": rootDir(0o777) },
    { "/etc": rootDir(0o1777) },
  ];
  for (const override of unsafe) {
    const { io } = fakeFs(baseTree(policy(["/srv/pluton-restore"]), override));
    await assert.rejects(readRestorePolicy(context(io)), /restore-policy-not-protected/);
    const report = await restoreAccessReport(context(io));
    assert.deepEqual(report, {
      version: 1,
      roots: [],
      policyError: "restore-policy-not-protected",
    });
  }
});

test("restore root checks report closed statuses without creating anything", async () => {
  const tree = baseTree(undefined, {
    "/srv/owned-by-root": { type: "dir", uid: 0, mode: 0o700 },
    "/srv/group-readable": { type: "dir", uid: AGENT_UID, mode: 0o750 },
    "/srv/link": { type: "link", uid: 0, mode: 0o777, target: "/srv/pluton-restore" },
    "/srv/shared": { type: "dir", uid: AGENT_UID, mode: 0o777 },
    "/srv/shared/restore": { type: "dir", uid: AGENT_UID, mode: 0o700 },
    "/srv/readonly": { type: "dir", uid: AGENT_UID, mode: 0o700, writable: false },
    "/srv/file": { type: "file", uid: AGENT_UID, mode: 0o600 },
  });
  const { io, nodes } = fakeFs(tree);
  const before = nodes.size;
  const expectations: [string, string, string?][] = [
    ["/srv/pluton-restore", "writable"],
    ["/srv/owned-by-root", "rejected", "restore-root-owner"],
    ["/srv/group-readable", "rejected", "restore-root-mode"],
    ["/srv/link", "rejected", "restore-root-not-directory"],
    ["/srv/shared/restore", "rejected", "restore-root-ancestor-unsafe"],
    ["/srv/readonly", "unavailable", "restore-root-not-writable"],
    ["/srv/missing", "unavailable", "restore-root-missing"],
    ["/srv/file", "rejected", "restore-root-not-directory"],
    ["/srv", "rejected", "restore-root-denied"],
    ["/tmp/restore", "rejected", "restore-root-denied"],
    ["/usr/local/restore", "rejected", "restore-root-denied"],
    ["/etc/restore", "rejected", "restore-root-denied"],
    ["/var/lib/pluton-agent/restore", "rejected", "restore-root-denied"],
    ["/srv/example-app/restore", "rejected", "restore-root-overlap"],
    ["/srv/example-app", "rejected", "restore-root-overlap"],
    ["relative", "rejected", "restore-root-invalid"],
  ];
  for (const [root, status, code] of expectations) {
    const report = await inspectRestoreRoot(context(io), root);
    assert.equal(report.status, status, root);
    assert.equal(report.code, code, root);
  }
  const writable = await inspectRestoreRoot(context(io), "/srv/pluton-restore");
  assert.equal(writable.availableBytes, 4096 * 1_000_000);
  assert.equal(writable.availableInodes, 400_000);
  assert.equal(nodes.size, before, "inspection never creates a path");
  // A root above the Agent state directory overlaps it.
  assert.equal(
    restoreRootLexicallyAllowed("/var/lib/pluton-agent", config, []),
    "restore-root-denied",
  );
  assert.equal(
    restoreRootLexicallyAllowed("/srv/pluton-restore", { ...config, dataDir: "/srv/pluton-restore/state" }, []),
    "restore-root-overlap",
  );
});

test("a non-canonical root is refused", async () => {
  const { io } = fakeFs(baseTree());
  const realpath = io.realpath;
  io.realpath = async (name) =>
    name === "/srv/pluton-restore" ? "/srv/elsewhere" : realpath(name);
  assert.equal(
    (await inspectRestoreRoot(context(io), "/srv/pluton-restore")).code,
    "restore-root-not-canonical",
  );
});

test("execution authorizes only a root that is in the policy and still writable", async () => {
  const { io, nodes } = fakeFs(
    baseTree(policy(["/srv/pluton-restore", "/srv/other-restore"]), {
      "/srv/other-restore": { type: "dir", uid: AGENT_UID, mode: 0o755 },
    }),
  );
  assert.deepEqual(await approvedRestoreRoot(context(io), "/srv/pluton-restore"), {
    root: "/srv/pluton-restore",
    availableBytes: 4096 * 1_000_000,
    availableInodes: 400_000,
  });
  await assert.rejects(
    approvedRestoreRoot(context(io), "/srv/unlisted"),
    /restore-root-not-approved/,
  );
  await assert.rejects(
    approvedRestoreRoot(context(io), "/srv/other-restore"),
    /restore-root-mode/,
  );
  const report = await restoreAccessReport(context(io));
  assert.deepEqual(
    report.roots.map(({ path, status, code }) => ({ path, status, code })),
    [
      { path: "/srv/other-restore", status: "rejected", code: "restore-root-mode" },
      { path: "/srv/pluton-restore", status: "writable", code: undefined },
    ],
  );
  nodes.delete(POLICY);
  await assert.rejects(
    approvedRestoreRoot(context(io), "/srv/pluton-restore"),
    /restore-root-not-approved/,
  );
});

test("known source roots include every reported source path", () => {
  assert.deepEqual(
    knownSourceRoots(config, {
      version: 1,
      hostPolicyRevision: "a".repeat(64),
      effectiveVersion: 1,
      approvedRoots: ["/srv/approved"],
      effectiveRoots: ["/srv/effective"],
      delegatedRoots: ["/srv/delegated"],
      rootStatuses: [{ path: "/srv/selected", status: "missing" }],
    }).sort(),
    ["/srv/approved", "/srv/delegated", "/srv/effective", "/srv/example-app", "/srv/selected"],
  );
});

test("the local CLI approves and revokes roots durably, as root only", async () => {
  const { io, nodes } = fakeFs(baseTree());
  nodes.delete("/etc/pluton-agent");
  const operator = (uid: number) => ({ ...context(io), operatorUid: uid });
  await assert.rejects(
    changeRestoreRoots(operator(AGENT_UID), { action: "approve", roots: ["/srv/pluton-restore"] }),
    /restore-host-operator-required/,
  );
  const approved = await changeRestoreRoots(operator(0), {
    action: "approve",
    roots: ["/srv/pluton-restore"],
  });
  assert.equal(approved.hostVersion, 1);
  assert.deepEqual(approved.roots.map((root) => root.status), ["writable"]);
  assert.equal(nodes.get("/etc/pluton-agent")?.mode, 0o755);
  const written = JSON.parse(nodes.get(POLICY)!.content!);
  assert.deepEqual(written, policy(["/srv/pluton-restore"]));
  assert.equal(nodes.get(POLICY)!.mode, 0o644);
  assert.equal(
    [...nodes.keys()].some((name) => name.endsWith(".tmp")),
    false,
    "no temporary policy file remains",
  );
  await assert.rejects(
    changeRestoreRoots(operator(0), { action: "approve", roots: ["/srv/pluton-restore"] }),
    /restore-policy-invalid/,
  );
  await assert.rejects(
    changeRestoreRoots(operator(0), { action: "approve", roots: ["/srv/example-app/restore"] }),
    /restore-root-overlap/,
  );
  await assert.rejects(
    changeRestoreRoots(operator(0), { action: "approve", roots: ["/srv/missing"] }),
    /restore-root-missing/,
  );
  await assert.rejects(
    changeRestoreRoots(operator(0), { action: "revoke", roots: ["/srv/other"] }),
    /restore-root-not-approved/,
  );
  const revoked = await changeRestoreRoots(operator(0), {
    action: "revoke",
    roots: ["/srv/pluton-restore"],
  });
  assert.equal(revoked.hostVersion, 2);
  assert.deepEqual(JSON.parse(nodes.get(POLICY)!.content!).roots, []);
  assert.equal(nodes.get("/srv/pluton-restore")?.mode, 0o700, "a root is never changed");
});
