import path from "node:path";

export type SourceProblem = {
  relativePath?: string;
  entryType: "file" | "directory" | "symlink" | "other" | "unknown";
  errno: "EACCES" | "EPERM" | "ENOENT" | "ENOTDIR" | "ELOOP" | "UNKNOWN";
  excluded: false;
};

export type SourceDiagnostics = {
  version: 1;
  origin: "preflight" | "restic";
  problemCount: number;
  countIsLowerBound: boolean;
  entries: SourceProblem[];
};

/** Filenames can themselves contain credentials or terminal controls. Omit an
 * unsafe name; never truncate it into a different, apparently valid filename. */
export function safeRelativePath(value: string): string | undefined {
  if (value === ".") return value;
  if (
    !value ||
    value.length > 512 ||
    /\p{M}{4,}/u.test(value) ||
    !/^[\p{L}\p{N}\p{M} ._+@()[\]{}!#$%&',;~/-]+$/u.test(value) ||
    value.startsWith("/") ||
    value.split("/").some((p) => !p || p === "." || p === "..") ||
    /(?:password|token|secret|credential|key)\s*=|-----BEGIN|:\/\//i.test(value)
  )
    return;
  return value;
}

export function relativeSourcePath(
  root: string,
  entry: string,
): string | undefined {
  const relative = path.relative(root, entry).split(path.sep).join("/");
  return safeRelativePath(relative || ".");
}

export function sourceErrno(value: unknown): SourceProblem["errno"] {
  return ["EACCES", "EPERM", "ENOENT", "ENOTDIR", "ELOOP"].includes(
    String(value),
  )
    ? (value as SourceProblem["errno"])
    : "UNKNOWN";
}

/** Counts observations, including repeated Restic reports; bounded representative
 * samples are deliberately not claimed to be a complete inventory. */
export function addSourceProblem(
  report: SourceDiagnostics,
  problem: SourceProblem,
): void {
  report.problemCount = Math.min(
    Number.MAX_SAFE_INTEGER,
    report.problemCount + 1,
  );
  if (report.entries.length < 20) report.entries.push(problem);
}

export function newSourceDiagnostics(
  origin: SourceDiagnostics["origin"],
): SourceDiagnostics {
  return {
    version: 1,
    origin,
    problemCount: 0,
    countIsLowerBound: true,
    entries: [],
  };
}

/** Only Restic JSON source records qualify. Storage/provider text and file
 * contents are never copied. Restic does not report entry type reliably. */
export function sourceProblemFromRestic(
  line: string,
  root: string,
  excluded: (relative: string) => boolean = () => false,
): SourceProblem | undefined {
  if (line.length > 65536) return;
  try {
    const record = JSON.parse(line);
    if (
      record?.message_type !== "error" ||
      !["scan", "archival"].includes(record.during) ||
      typeof record.item !== "string" ||
      record.item.length > 4096 ||
      !path.isAbsolute(record.item)
    )
      return;
    const relative = path.relative(root, record.item).split(path.sep).join("/");
    if (
      relative === ".." ||
      relative.startsWith("../") ||
      path.isAbsolute(relative) ||
      excluded(relative)
    )
      return;
    const message =
      typeof record.error?.message === "string" ? record.error.message : "";
    const errno = /operation not permitted/i.test(message)
      ? "EPERM"
      : /permission denied/i.test(message)
        ? "EACCES"
        : /no such file|not found/i.test(message)
          ? "ENOENT"
          : undefined;
    if (!errno) return;
    return {
      relativePath: safeRelativePath(relative || "."),
      entryType: "unknown",
      errno,
      excluded: false,
    };
  } catch {
    return;
  }
}
