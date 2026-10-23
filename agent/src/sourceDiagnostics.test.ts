import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import path from "node:path";
import os from "node:os";
import {
  addSourceProblem,
  newSourceDiagnostics,
  safeRelativePath,
  sourceProblemFromRestic,
} from "./sourceDiagnostics.js";
import { preflightSource, SourceAccessError } from "./filesystemPolicy.js";
import { toBackupFilesystemError } from "./backupFilesystem.js";
import { compileBackupExclusions } from "./backupExclusions.js";

test("Restic diagnostics retain only contained names and observed closed categories", () => {
  const root = path.resolve("/srv/example-app");
  const record = (item: string, message = "open: permission denied") =>
    JSON.stringify({
      message_type: "error",
      during: "archival",
      item,
      error: { message },
      contents: "synthetic private contents",
    });
  const item = path.join(root, "app/logs/id_rsa");
  assert.deepEqual(sourceProblemFromRestic(record(item), root), {
    relativePath: "app/logs/id_rsa",
    entryType: "unknown",
    errno: "EACCES",
    excluded: false,
  });
  assert.equal(
    sourceProblemFromRestic(record(item, "operation not permitted"), root)
      ?.errno,
    "EPERM",
  );
  assert.equal(
    sourceProblemFromRestic(record(item, "no such file or directory"), root)
      ?.errno,
    "ENOENT",
  );
  for (const value of [
    record(path.resolve(root, "../outside")),
    record("relative"),
    "sftp permission denied",
    record(item, "storage offline"),
  ])
    assert.equal(sourceProblemFromRestic(value, root), undefined);
  assert.equal(
    sourceProblemFromRestic(
      record(item),
      root,
      compileBackupExclusions(["app/logs"]),
    ),
    undefined,
  );
  assert.ok(
    !JSON.stringify(sourceProblemFromRestic(record(item), root)).includes(
      "synthetic private contents",
    ),
  );
});

test("unsafe names are withheld; spaces, Unicode and sensitive basenames are not invented or rewritten", () => {
  for (const name of [
    "report with spaces.pdf",
    "資料/café.pdf",
    "app/logs/id_rsa",
  ])
    assert.equal(safeRelativePath(name), name);
  for (const name of [
    "/absolute",
    "../escape",
    "a/../b",
    "a\\b",
    "a\nb",
    "a\u001bb",
    "a\u202eb",
    "a" + "\u0301".repeat(10),
    "a\ud800b",
    "a".repeat(513),
    "token=synthetic",
    "-----BEGIN PRIVATE KEY-----",
  ])
    assert.equal(safeRelativePath(name), undefined);
  const report = newSourceDiagnostics("restic");
  for (let i = 0; i < 5000; i++)
    addSourceProblem(report, {
      relativePath: `entry-${i}`,
      errno: "EACCES",
      entryType: "unknown",
      excluded: false,
    });
  assert.equal(report.entries.length, 20);
  assert.equal(report.problemCount, 5000);
  assert.ok(JSON.stringify(report).length < 12000);
  const failure = toBackupFilesystemError(
    new SourceAccessError(
      "source-entry-inaccessible",
      "/synthetic-root",
      undefined,
      undefined,
      report,
    ),
    "restic-backup",
  );
  assert.equal(failure.sourceDiagnostics, report);
  assert.ok(!failure.message.includes("entry-"));
  assert.ok(!failure.message.includes("/synthetic-root"));
});

const linux = process.platform === "linux" && process.getuid?.() !== 0;
test(
  "bounded preflight aggregates unreadable files/directories and prunes excluded subtrees",
  { skip: !linux },
  async (t) => {
    const root = await fs.mkdtemp(
      path.join(os.tmpdir(), "pluton-diagnostics-"),
    );
    t.after(async () => {
      await fs.chmod(path.join(root, "denied-directory"), 0o700);
      await fs.chmod(path.join(root, "excluded"), 0o700);
      await fs.rm(root, { recursive: true, force: true });
    });
    for (const name of ["denied-directory", "excluded"]) {
      await fs.mkdir(path.join(root, name));
      await fs.chmod(path.join(root, name), 0);
    }
    for (let i = 0; i < 25; i++)
      await fs.writeFile(
        path.join(root, `denied file ${i}`),
        "synthetic private contents",
        { mode: 0 },
      );
    await assert.rejects(
      preflightSource(root, [root], {
        scan: true,
        collectProblems: true,
        exclusions: ["excluded"],
      }),
      (error: unknown) => {
        assert.ok(error instanceof SourceAccessError);
        assert.equal(error.code, "source-entry-inaccessible");
        const report = error.sourceDiagnostics!;
        assert.equal(report.problemCount, 26);
        assert.equal(report.entries.length, 20);
        assert.ok(
          report.entries.every(
            (e) => e.errno === "EACCES" && e.relativePath !== "excluded",
          ),
        );
        assert.ok(!JSON.stringify(report).includes(root));
        assert.ok(
          !JSON.stringify(report).includes("synthetic private contents"),
        );
        return true;
      },
    );
  },
);

test("a disappearing scan entry retains ENOENT without becoming a permission error", async (t) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "pluton-transient-"));
  const gone = path.join(root, "disappearing");
  const goneDirectory = path.join(root, "disappearing-directory");
  await fs.writeFile(gone, "synthetic");
  await fs.mkdir(goneDirectory);
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const original = fs.lstat;
  t.mock.method(fs, "lstat", async (name: Parameters<typeof fs.lstat>[0]) => {
    if (name === gone)
      throw Object.assign(new Error("synthetic vanished entry"), {
        code: "ENOENT",
      });
    return original(name);
  });
  const originalRealpath = fs.realpath;
  t.mock.method(
    fs,
    "realpath",
    async (name: Parameters<typeof fs.realpath>[0]) => {
      if (name === goneDirectory)
        throw Object.assign(new Error("synthetic vanished directory"), {
          code: "ENOENT",
        });
      return originalRealpath(name);
    },
  );
  syncBuiltinESMExports();
  t.after(() => {
    t.mock.restoreAll();
    syncBuiltinESMExports();
  });
  await assert.rejects(
    preflightSource(root, [root], { scan: true, collectProblems: true }),
    (error: unknown) => {
      assert.ok(error instanceof SourceAccessError);
      assert.equal(error.code, "source-missing");
      assert.equal(error.sourceDiagnostics?.problemCount, 2);
      assert.ok(
        error.sourceDiagnostics?.entries.every(
          (entry) => entry.errno === "ENOENT",
        ),
      );
      assert.ok(
        error.sourceDiagnostics?.entries.some(
          (entry) => entry.relativePath === "disappearing",
        ),
      );
      assert.ok(
        error.sourceDiagnostics?.entries.some(
          (entry) =>
            entry.relativePath === "disappearing-directory" &&
            entry.entryType === "directory",
        ),
      );
      return true;
    },
  );
});

test("scan never follows nested links and reports resource-limited inspection honestly", async (t) => {
  const root = await fs.mkdtemp(
    path.join(os.tmpdir(), "pluton-diagnostics-tree-"),
  );
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const source = path.join(root, "source"),
    outside = path.join(root, "outside");
  await fs.mkdir(source);
  await fs.mkdir(outside);
  await fs.writeFile(
    path.join(outside, "private"),
    "synthetic private contents",
  );
  try {
    await fs.symlink(outside, path.join(source, "escape"), "junction");
  } catch {
    t.skip("Test platform cannot create symlinks");
    return;
  }
  assert.equal(
    (
      await preflightSource(source, [source], {
        scan: true,
        collectProblems: true,
      })
    ).linksNotFollowed,
    1,
  );
  await assert.rejects(
    preflightSource(path.join(source, "escape"), [source]),
    (e: unknown) =>
      e instanceof SourceAccessError && e.code === "source-symlink-escape",
  );
  for (let i = 0; i < 200; i++)
    await fs.writeFile(path.join(source, `entry-${i}`), "synthetic");
  const bounded = await preflightSource(source, [source], {
    scan: true,
    collectProblems: true,
    maxEntries: 10,
  });
  assert.equal(bounded.scan, "entry-limit");
  assert.equal(bounded.entriesChecked, 10);
});
