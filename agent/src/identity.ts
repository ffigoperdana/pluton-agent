import path from 'node:path';
import { chmod, mkdir, readFile, rename, writeFile, lstat, rmdir, open, link, unlink } from 'node:fs/promises';
import type { StoredAgentIdentity } from './types.js';

const IDENTITY_FILE = 'identity.json';

export function identityPath(dataDir: string): string {
	return path.join(dataDir, IDENTITY_FILE);
}

const enrollmentConflict = () => new Error('Existing identity or enrollment state requires operator review.');

async function requireNoIdentity(dataDir: string): Promise<void> {
	try { await lstat(identityPath(dataDir)); }
	catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT') return; throw error; }
	throw enrollmentConflict();
}

export async function lockEnrollment(dataDir: string): Promise<() => Promise<void>> {
	await requireNoIdentity(dataDir);
	await mkdir(dataDir, { recursive: true, mode: 0o700 });
	if (!(await lstat(dataDir)).isDirectory()) throw enrollmentConflict();
	const lock = path.join(dataDir, '.enrollment-lock');
	try { await mkdir(lock, { mode: 0o700 }); }
	catch { throw enrollmentConflict(); }
	try { await requireNoIdentity(dataDir); }
	catch (error) { await rmdir(lock); throw error; }
	return () => rmdir(lock);
}

/** Enrollment creates a new identity; it never replaces another enrollment. */
export async function saveEnrollmentIdentity(dataDir: string, identity: StoredAgentIdentity): Promise<void> {
	const temporary = path.join(dataDir, `.enrollment-${process.pid}.tmp`);
	const file = await open(temporary, 'wx', 0o600);
	try {
		await file.writeFile(`${JSON.stringify(identity)}\n`, 'utf8');
		await file.sync();
	} finally { await file.close(); }
	try {
		await link(temporary, identityPath(dataDir));
		const directory = await open(dataDir, 'r');
		try { if (process.platform !== 'win32') await directory.sync(); }
		finally { await directory.close(); }
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === 'EEXIST') throw enrollmentConflict();
		throw error;
	} finally { await unlink(temporary); }
}

async function protect(pathname: string, mode: number): Promise<void> {
	try {
		await chmod(pathname, mode);
	} catch {
		// Windows does not implement POSIX modes. Linux deployments are checked by chmod.
	}
}

export async function saveIdentity(dataDir: string, identity: StoredAgentIdentity): Promise<void> {
	await mkdir(dataDir, { recursive: true, mode: 0o700 });
	await protect(dataDir, 0o700);
	const destination = identityPath(dataDir);
	const temporary = `${destination}.${process.pid}.tmp`;
	await writeFile(temporary, `${JSON.stringify(identity)}\n`, { encoding: 'utf8', mode: 0o600 });
	await protect(temporary, 0o600);
	await rename(temporary, destination);
	await protect(destination, 0o600);
}

export async function loadIdentity(dataDir: string): Promise<StoredAgentIdentity> {
	const raw = await readFile(identityPath(dataDir), 'utf8');
	const parsed = JSON.parse(raw) as Partial<StoredAgentIdentity>;
	if (
		!parsed.deviceId ||
		!parsed.agentId ||
		!parsed.secret ||
		!Number.isInteger(parsed.pollIntervalSeconds) ||
		!Array.isArray(parsed.completedCommands)
	) {
		throw new Error('Agent identity file is invalid. Re-enroll this agent.');
	}
	return parsed as StoredAgentIdentity;
}
