"use strict";
// Optional runtime participant in the existing drained app transaction. No
// identity/config/policy restoration, enrollment or in-place binary replacement.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { GuardFailure } = require("./upgrade-diagnostics.cjs");
const TARGET_NODE = "v22.23.4";
const ARCHIVE_SHA256 = "1805bcd35e6815559bd2eb97db438d3fdb0eb3a5e6a977b7c1badca76337e9ce";
const SUPPORTED_NODES = new Set(["v22.18.0", TARGET_NODE]);
const sha = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const exists = (file) => { try { fs.lstatSync(file); return true; } catch (e) { if (e.code === "ENOENT") return false; throw e; } };
const requireSafe = (condition) => { if (!condition) throw new GuardFailure("Runtime transaction integrity or ownership check failed."); };

function digest(root, c) {
  const entries = [];
  const visit = (file, relative) => {
    const s = fs.lstatSync(file);
    requireSafe(s.uid === c.owner);
    if (s.isSymbolicLink()) {
      const target = fs.realpathSync(file);
      requireSafe(target.startsWith(root + path.sep));
      entries.push([relative, "link", fs.readlinkSync(file)]);
    } else {
      requireSafe((s.isDirectory() || (s.isFile() && s.nlink === 1)) && (!c.enforceModes || !(s.mode & 0o022)));
      entries.push([relative, s.mode & 0o777, s.isFile() ? sha(fs.readFileSync(file)) : "directory"]);
      if (s.isDirectory()) for (const name of fs.readdirSync(file).sort()) visit(path.join(file, name), `${relative}/${name}`);
    }
  };
  requireSafe(!fs.lstatSync(root).isSymbolicLink());
  visit(root, ".");
  return sha(JSON.stringify(entries));
}
function copy(from, to, c, syncTree) {
  const expected = digest(from, c);
  requireSafe(!exists(to));
  fs.cpSync(from, to, { recursive: true, force: false, errorOnExist: true, preserveTimestamps: true, verbatimSymlinks: true });
  requireSafe(digest(to, c) === expected);
  // Links were checked to remain inside this runtime; sync their containing
  // directories, never dereference them as files.
  syncTree(to, c.sync, to);
}
function anchor(c, syncFile) {
  const destination = path.join(c.hold, "node");
  fs.copyFileSync(c.node, destination, fs.constants.COPYFILE_EXCL);
  fs.chmodSync(destination, 0o500);
  requireSafe(sha(fs.readFileSync(destination)) === fs.readFileSync(path.join(c.hold, "node.sha256"), "utf8"));
  syncFile(destination);
  c.sync(c.hold);
}
function record(c) {
  return c.runtimeChange ? { previous: digest(c.runtime, c), target: TARGET_NODE } : undefined;
}
function paths(c, r) {
  requireSafe(c.runtime && r.runtime && r.runtime.target === TARGET_NODE && /^[a-f0-9]{64}$/.test(r.runtime.previous));
  return {
    next: path.join(c.install, `.next-runtime-${r.id}`),
    previous: path.join(c.install, `.previous-runtime-${r.id}`),
    backup: path.join(c.backups, r.id, "runtime"),
  };
}
function unchanged(c, r) {
  if (r.runtime) requireSafe(digest(c.runtime, c) === r.runtime.previous);
}
function candidate(c, r, syncTree) {
  if (!r.runtime) return;
  const p = paths(c, r);
  r.runtime.candidate = digest(p.next, c);
  syncTree(p.next, c.sync, p.next);
  unchanged(c, r);
}
function backup(c, r, syncTree) {
  if (!r.runtime) return;
  unchanged(c, r);
  copy(c.runtime, paths(c, r).backup, c, syncTree);
}
function activate(c, r) {
  if (!r.runtime) return;
  const p = paths(c, r);
  requireSafe(!exists(p.previous) && digest(p.next, c) === r.runtime.candidate);
  unchanged(c, r);
  fs.renameSync(c.runtime, p.previous);
  c.sync(c.install);
  c.checkpoint("runtime-old-moved");
  fs.renameSync(p.next, c.runtime);
  c.sync(c.install);
  c.checkpoint("runtime-activated");
}
function healthy(c, r) {
  if (r.runtime) requireSafe(digest(c.runtime, c) === r.runtime.candidate);
}
function assertRollback(c, r) {
  if (!r.runtime) return;
  const p = paths(c, r);
  requireSafe(/^[a-f0-9]{64}$/.test(r.runtime.candidate || "") && digest(p.backup, c) === r.runtime.previous);
  if (exists(c.runtime)) {
    const current = digest(c.runtime, c);
    requireSafe(current === r.runtime.previous || current === r.runtime.candidate);
  }
  if (exists(p.previous)) requireSafe(digest(p.previous, c) === r.runtime.previous);
}
function restore(c, r, syncTree) {
  if (!r.runtime) return;
  assertRollback(c, r);
  const p = paths(c, r);
  if (exists(c.runtime)) {
    if (digest(c.runtime, c) === r.runtime.previous) return;
    const failed = path.join(c.install, `.failed-runtime-${r.id}`);
    requireSafe(!exists(failed));
    fs.renameSync(c.runtime, failed);
    c.sync(c.install);
  }
  if (exists(p.previous)) { fs.renameSync(p.previous, c.runtime); c.sync(c.install); }
  else copy(p.backup, c.runtime, c, syncTree);
}
module.exports = { TARGET_NODE, ARCHIVE_SHA256, SUPPORTED_NODES, digest, copy, anchor, record, candidate, unchanged, backup, activate, healthy, assertRollback, restore };
