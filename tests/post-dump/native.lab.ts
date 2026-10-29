/** Disposable real MySQL/dump + real Agent runtime + signed faulting control plane.
 * Provider output, SQL, credentials and signed bodies never leave the fixture. */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import net from 'node:net';
import { spawn, fork } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { chmodSync, readdirSync } from 'node:fs';
import { runOnce } from '../../agent/dist/runtime.js';
import { saveIdentity, loadIdentity } from '../../agent/dist/identity.js';
import { signRequest } from '../../agent/dist/protocol.js';

const baseline = process.argv.includes('--baseline');
const root = await fs.mkdtemp('/tmp/pluton-post-dump-');
const secret = () => crypto.randomBytes(32).toString('base64url');
const dbPassword = secret(),
	repoPassword = secret(),
	sftpPassword = secret(),
	agentSecret = secret();
const forbidden = [
	dbPassword,
	repoPassword,
	sftpPassword,
	agentSecret,
	process.env.FIXTURE_MYSQL_PASSWORD!,
];
const children: ReturnType<typeof spawn>[] = [];
async function run(binary: string, args: string[], input?: string, env: NodeJS.ProcessEnv = {}) {
	return new Promise<string>((resolve, reject) => {
		const child = spawn(binary, args, {
			env: { PATH: process.env.PATH, ...env },
			stdio: ['pipe', 'pipe', 'pipe'],
		});
		let stdout = '',
			stderr = '';
		child.stdout.on('data', chunk => {
			if (stdout.length < 1024 * 1024) stdout += chunk;
		});
		child.stderr.on('data', chunk => {
			if (stderr.length < 4096) stderr += chunk;
		});
		child.once('error', () => reject(new Error('Fixture native command unavailable.')));
		child.once('close', code =>
			code === 0
				? resolve(stdout)
				: reject(
						new Error(
							`Fixture native command refused (${/SSL|TLS|certificate/.test(stderr) ? 'tls' : /Access denied/.test(stderr) ? 'auth' : /connect|Unknown.*host/.test(stderr) ? 'connect' : /plugin/.test(stderr) ? 'plugin' : 'other'}).`
						)
					)
		);
		child.stdin.end(input);
	});
}
async function port() {
	const s = net.createServer();
	await new Promise<void>(r => s.listen(0, '127.0.0.1', r));
	const p = (s.address() as net.AddressInfo).port;
	await new Promise<void>(r => s.close(() => r()));
	return p;
}
const records: any[] = [];
let server: http.Server | undefined;
const originalInfo = console.info,
	originalError = console.error;
let current: any,
	postDump = false,
	dumpStarted = false,
	resticStarted = false,
	completions: any[] = [],
	statusCalls = 0,
	acknowledgements = 0,
	events = 0,
	applied = 0;
let fault = 'healthy',
	remaining = 0,
	completeUncertain = false;
let activeDataDir = '';
const journal: string[] = [];
async function nativePids(name: string): Promise<number[]> {
	const pids: number[] = [];
	for (const entry of await fs.readdir('/proc')) {
		if (!/^\d+$/.test(entry)) continue;
		try {
			if (path.basename(await fs.readlink(`/proc/${entry}/exe`)) === name) pids.push(Number(entry));
		} catch { /* Not our process, or already exited. */ }
	}
	return pids;
}
const nativeDumpFaults = ['cancel-during-dump', 'lease-during-dump', 'network-during-dump'];
try {
	assert.notEqual(process.getuid?.(), 0);
	assert.equal(process.version, 'v22.23.4', 'Native acceptance must use the pinned standalone runtime.');
	const admin = path.join(root, 'admin.cnf');
	await fs.writeFile(
		admin,
		`[client]\nhost=127.0.0.1\nprotocol=tcp\nuser=root\npassword=${process.env.FIXTURE_MYSQL_PASSWORD}\n`,
		{ mode: 0o600 }
	);
	for (let n = 0; ; n++) {
		try {
			await run('/usr/bin/mysql', [`--defaults-file=${admin}`, '-e', 'SELECT 1']);
			break;
		} catch (error) {
			assert(
				n < 120,
				error instanceof Error ? error.message : 'Disposable MySQL did not become ready.'
			);
			await new Promise(r => setTimeout(r, 500));
		}
	}
	const version = await run('/usr/bin/mysql', [
		`--defaults-file=${admin}`,
		'-Nse',
		'SELECT VERSION()',
	]);
	assert.match(version, /^8\./);
	await run(
		'/usr/bin/mysql',
		[`--defaults-file=${admin}`],
		`CREATE DATABASE example_db; CREATE TABLE example_db.fixture (id INT PRIMARY KEY, value VARCHAR(64)); INSERT INTO example_db.fixture VALUES (1,'synthetic fixture'); CREATE USER 'backup_reader'@'%' IDENTIFIED BY '${dbPassword}'; GRANT SELECT, SHOW VIEW, TRIGGER ON example_db.* TO 'backup_reader'@'%';`
	);
	const source = path.join(root, 'source');
	await fs.mkdir(source);
	await fs.writeFile(path.join(source, 'app.txt'), 'synthetic source\n', { mode: 0o600 });
	const storage = path.join(root, 'storage');
	await fs.mkdir(storage);
	const sftpPort = await port();
	const sftp = spawn(
		'/usr/local/bin/rclone',
		[
			'serve',
			'sftp',
			storage,
			'--addr',
			`127.0.0.1:${sftpPort}`,
			'--user',
			'fixture',
			'--pass',
			sftpPassword,
			'--cache-dir',
			path.join(root, 'cache'),
			'--config',
			path.join(root, 'rclone.conf'),
		],
		{
			stdio: 'ignore',
			env: { ...process.env, HOME: root, XDG_CACHE_HOME: path.join(root, 'cache') },
		}
	);
	children.push(sftp);
	for (let n = 0; ; n++) {
		const ready = await new Promise<boolean>(r => {
			const s = net.createConnection({ host: '127.0.0.1', port: sftpPort });
			s.once('connect', () => {
				s.destroy();
				r(true);
			});
			s.once('error', () => r(false));
		});
		if (ready) break;
		assert(n < 120);
		await new Promise(r => setTimeout(r, 25));
	}
	const nonces = new Set<string>();
	let leaseUntil = Date.now() + 60_000;
	server = http.createServer(async (req, res) => {
		let raw = '';
		for await (const chunk of req) raw += chunk;
		const h = req.headers;
		const stamp = String(h['x-pluton-agent-timestamp']),
			nonce = String(h['x-pluton-agent-nonce']);
		assert.equal(h['x-pluton-agent-id'], 'agent-01');
		assert(!nonces.has(nonce));
		nonces.add(nonce);
		assert(
			h['x-pluton-agent-signature'] ===
				signRequest(agentSecret, stamp, nonce, 'POST', req.url!, raw),
			'Signed request verification failed.'
		);
		const body = JSON.parse(raw);
		let result: any = {};
		let code = 200;
		if (req.url === '/api/agent/poll') result = { command: current };
		else if (req.url?.endsWith('/ack')) acknowledgements++;
		else if (req.url?.endsWith('/status')) {
			assert(body.leaseToken === current.leaseToken, 'Lease ownership mismatch.');
			statusCalls++;
			if (dumpStarted && !postDump && nativeDumpFaults.includes(fault) && (await nativePids('mysqldump')).length) {
				if (fault === 'network-during-dump') { req.socket.destroy(); return; }
				if (fault === 'lease-during-dump') {
					res.writeHead(404);
					res.end('{}');
					return;
				}
				result = { cancelled: true };
			}
			if (resticStarted && fault === 'restic-cancelled') result = { cancelled: true };
			if (postDump) {
				applied++;
				if ((remaining-- > 0 || remaining === -1001) && fault !== 'healthy') {
					if (fault === 'network') {
						req.socket.destroy();
						return;
					}
					if (fault === 'timeout') {
						return;
					}
					if (fault === 'invalid-json') {
						res.writeHead(200);
						res.end('{');
						return;
					}
					if (fault === 'invalid-schema') {
						result = { cancelled: 'false' };
					} else if (fault === 'cancelled') {
						result = { cancelled: true };
					} else if (fault === 'lease') {
						code = 404;
					} else if (fault === 'expired-lease') {
						result = { cancelled: false, leaseExpiresAt: new Date(0).toISOString() };
					} else if (fault === 'auth') {
						code = 403;
					} else code = Number(fault);
				}
			}
			if (code === 200 && !Object.keys(result).length) {
				leaseUntil = Date.now() + 60_000;
				result = fault === 'legacy-status' ? { cancelled: false }
					: { cancelled: false, leaseExpiresAt: new Date(leaseUntil).toISOString() };
			}
		} else if (req.url?.endsWith('/events')) {
			events++;
			if (fault === 'events429') code = 429;
		} else if (req.url?.endsWith('/complete')) {
			completions.push(body);
			if (completeUncertain) {
				completeUncertain = false;
				req.socket.destroy();
				return;
			}
		}
		res.writeHead(code, { 'content-type': 'application/json' });
		// Exercise the standalone void ACK/event/completion contract directly.
		res.end(JSON.stringify({ success: code === 200,
			...(!/\/(?:ack|events|complete)$/.test(req.url!) ? { result } : {}) }));
	});
	await new Promise<void>(r => server!.listen(0, '127.0.0.1', r));
	const serverUrl = new URL(`http://127.0.0.1:${(server.address() as net.AddressInfo).port}`);
	console.info = (...args: any[]) => {
		const text = args.join(' ');
		journal.push(text);
		if (text.includes('database-dump-started')) dumpStarted = true;
		if (text.includes('database-dump-completed')) postDump = true;
		if (fault === 'restic-cancelled' && text.includes('restic backup started')) {
			resticStarted = true;
			sftp.kill('SIGSTOP'); // Hold native Restic at disposable storage until its cancellation poll.
		}
		if (fault === 'journal-throw' && text.includes('stage=post-dump-status-check'))
			throw new Error('Synthetic journal callback failure.');
		if (postDump && fault === 'finalization' && text.includes('database-dump-completed')) {
			for (const name of readdirSync(path.join(activeDataDir, 'jobs')))
				chmodSync(path.join(activeDataDir, 'jobs', name), 0o500);
		}
		if (postDump && fault === 'repository' && text.includes('database-dump-completed'))
			sftp.kill('SIGTERM');
	};
	console.error = (...args: any[]) => journal.push(args.join(' '));
	const scenarios = baseline
		? [['503', 1000]]
		: [
				['healthy', 0],
				['legacy-status', 0],
				['events429', 0],
				['429', 1],
				['502', 1],
				['503', 1],
				['429', 1000],
				['503', 1000],
				['timeout', 1000],
				['network', 1000],
				['invalid-json', 1000],
				['invalid-schema', 1000],
				['lease', 1000],
				['expired-lease', 1000],
				['auth', 1000],
				['cancelled', 1000],
				['uncertain-completion', 0],
				['journal-throw', 0],
				['cancel-during-dump', 0],
				['lease-during-dump', 0],
				['network-during-dump', 0],
				['restic-cancelled', 0],
				['finalization', 0],
				['repository', 0],
			];
	for (let i = 0; i < scenarios.length; i++) {
		[fault, remaining] = scenarios[i] as [string, number];
		const transientRecovery = ['429', '502', '503'].includes(fault) && remaining === 1;
		postDump = false;
		dumpStarted = false;
		resticStarted = false;
		statusCalls = acknowledgements = events = applied = 0;
		completions = [];
		const dataDir = path.join(root, `state-${i}`);
		activeDataDir = dataDir;
		await fs.mkdir(dataDir, { mode: 0o700 });
		await saveIdentity(dataDir, {
			deviceId: 'device-01',
			agentId: 'agent-01',
			secret: agentSecret,
			pollIntervalSeconds: 5,
			completedCommands: [],
		});
		current = {
			id: `command-${i}`,
			type: 'BACKUP_FILESYSTEM',
			idempotencyKey: `backup:${i}`,
			leaseToken: secret(),
			leaseExpiresAt: new Date(Date.now() + 60_000).toISOString(),
			signatureTimestamp: String(Date.now()),
			payload: {
				version: 3,
				backupId: `backup-${i}`,
				planId: 'plan-01',
				sourcePath: source,
				excludes: [],
				repository: { remoteName: 'pluton', path: `managed/case-${i}`, initialize: true },
				repositoryPassword: repoPassword,
				rclone: {
					type: 'sftp',
					options: {
						host: '127.0.0.1',
						port: String(sftpPort),
						user: 'fixture',
						pass: sftpPassword,
					},
				},
				lifecycle: {
					version: 2,
					databases: [
						{
							databaseId: 'db_fixture',
							engine: 'mysql',
							host: '127.0.0.1',
							port: 3306,
							tls: 'local',
							database: 'example_db',
							username: 'backup_reader',
							password: dbPassword,
							dumpFilename: 'app.sql',
							timeoutSeconds: 60,
							maxDumpBytes: 4 * 1024 ** 2,
							includeRoutines: false,
							includeEvents: false,
						},
					],
				},
			},
		};
		const sign = () => {
			current.signature = crypto
				.createHmac('sha256', agentSecret)
				.update(
					[
						'command',
						current.signatureTimestamp,
						current.id,
						current.type,
						JSON.stringify(current.payload),
						current.idempotencyKey,
						current.leaseToken,
						Date.parse(current.leaseExpiresAt).toString(),
					].join('\n')
				)
				.digest('base64');
		};
		sign();
		const config = {
			serverUrl,
			dataDir,
			allowedRoots: [source],
			allowInsecureHttp: true,
			binDir: '/usr/local/bin',
			databaseBinDirs: ['/usr/bin'],
		};
		const started = performance.now();
		let blocker: ReturnType<typeof spawn> | undefined;
		if (nativeDumpFaults.includes(fault)) {
			blocker = spawn(
				'/usr/bin/mysql',
				[`--defaults-file=${admin}`, '--batch', '--skip-column-names', '--unbuffered'],
				{ stdio: ['pipe', 'pipe', 'ignore'] }
			);
			children.push(blocker);
			const locked = new Promise<void>((resolve, reject) => {
				blocker!.stdout!.once('data', () => resolve());
				blocker!.once('close', () => reject(new Error('Disposable table lock unavailable.')));
			});
			blocker.stdin!.end("LOCK TABLES example_db.fixture WRITE; SELECT 'locked'; DO SLEEP(60);");
			await locked;
		}
		completeUncertain = fault === 'uncertain-completion';
		let completionFailure = false;
		try {
			await runOnce(config);
		} catch (error) {
			if (fault !== 'uncertain-completion') throw error;
			completionFailure = true;
			assert.equal((error as any).stage, 'complete');
		}
		assert.equal(completionFailure, fault === 'uncertain-completion');
		blocker?.kill('SIGTERM');
		if (fault === 'restic-cancelled') sftp.kill('SIGCONT');
		assert.deepEqual(await nativePids('mysqldump'), [], 'Owned native dump must stop before cleanup.');
		assert.deepEqual(await nativePids('restic'), [], 'Owned Restic process must stop before completion.');
		if (fault !== 'repository') assert.equal((await nativePids('rclone')).length, 1,
			'Only the fixture SFTP listener may remain; Restic child transports must stop.');
		if (!postDump)
			originalInfo(
				JSON.stringify({
					event: 'fixture_boundary',
					dumpStarted,
					stage: completions[0]?.failureStage,
					code: completions[0]?.failureCode,
				})
			);
		assert(
			dumpStarted && (postDump || nativeDumpFaults.includes(fault)),
			'Real MySQL dump boundary was not reached.'
		);
		assert.equal(completions.length, 1);
		const completion = completions[0];
		if (baseline) {
			assert.equal(completion.failureStage, 'database-dump');
			assert.equal(completion.failureCode, 'unexpected');
			assert(!journal.some(s => s.includes('stage=repository-target-check')));
		} else if (
			['healthy', 'legacy-status', 'events429', 'uncertain-completion', 'journal-throw'].includes(fault) ||
			transientRecovery
		) {
			assert.equal(completion.success, true);
			assert.match(completion.result.snapshotId, /^[a-f0-9]{64}$/);
			const receipt = completion.result.lifecycle.databases[0];
			assert(receipt.bytes > 0);
			assert.match(receipt.sha256, /^[a-f0-9]{64}$/);
			const repo = path.join(storage, current.payload.repository.path);
			const sql = await run(
				'/usr/local/bin/restic',
				['--no-cache', '-r', repo, 'dump', completion.result.snapshotId, receipt.path],
				undefined,
				{ RESTIC_PASSWORD: repoPassword }
			);
			assert.equal(Buffer.byteLength(sql), receipt.bytes);
			assert.equal(crypto.createHash('sha256').update(sql).digest('hex'), receipt.sha256);
			const snapshots = JSON.parse(
				await run(
					'/usr/local/bin/restic',
					['--no-cache', '-r', repo, 'snapshots', '--json'],
					undefined,
					{ RESTIC_PASSWORD: repoPassword }
				)
			);
			assert.equal(snapshots.length, 1);
			assert.equal(snapshots[0].id, completion.result.snapshotId);
		} else {
			assert.equal(completion.success, false);
			assert.equal(
				completion.failureStage,
				fault === 'cancel-during-dump'
					? 'database-dump'
					: ['lease-during-dump', 'network-during-dump'].includes(fault)
						? 'command-status-check'
						: fault === 'restic-cancelled' ? 'restic-backup'
						: fault === 'finalization'
							? 'database-dump-validation'
							: fault === 'repository'
								? 'repository-target-check'
								: 'post-dump-status-check'
			);
			assert.notEqual(completion.failureCode, 'unexpected');
			const expected: Record<string, string> = {
				'429': 'control-plane-rate-limited', '503': 'control-plane-unavailable',
				timeout: 'control-plane-timeout', network: 'control-plane-network-failed',
				'invalid-json': 'control-plane-response-invalid', 'invalid-schema': 'control-plane-response-invalid',
				lease: 'command-lease-unavailable', 'expired-lease': 'command-lease-unavailable',
				auth: 'command-authorization-rejected', cancelled: 'cancelled',
				'cancel-during-dump': 'cancelled', 'restic-cancelled': 'cancelled',
				'lease-during-dump': 'command-lease-unavailable', 'network-during-dump': 'control-plane-network-failed',
			};
			if (expected[fault]) assert.equal(completion.failureCode, expected[fault]);
			if (fault === 'finalization')
				assert.equal(completion.failureCode, 'database-artifact-finalization-failed');
			assert.equal(completion.result, undefined, 'A partial dump cannot be reported successful.');
		}
		const files = await fs.readdir(dataDir);
		assert(!files.some(name => name.startsWith('job-')));
		if (fault === 'finalization') {
			assert(journal.some(text => text.includes('cleanup-warning')));
			for (const name of await fs.readdir(path.join(dataDir, 'jobs'))) {
				await fs.chmod(path.join(dataDir, 'jobs', name), 0o700);
				await fs.rm(path.join(dataDir, 'jobs', name), { recursive: true, force: true });
			}
		}
		assert.equal((await fs.readdir(path.join(dataDir, 'jobs'))).length, 0);
		// Persisted receipt replay after an uncertain completion must not execute again.
		const before = journal.filter(s => s.includes('database-dump-started')).length;
		const previous = JSON.stringify(completion);
		const ackBefore = acknowledgements, eventsBefore = events;
		postDump = false;
		remaining = 0;
		const child = fork(fileURLToPath(new URL('./restart.mjs', import.meta.url)), [], {
			stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
			env: { PATH: process.env.PATH },
		});
		await new Promise<void>((resolve, reject) => {
			const timer = setTimeout(() => {
				child.kill();
				reject(new Error('Fresh-process reconciliation deadline.'));
			}, 20_000);
			child.once('message', (message: any) => {
				clearTimeout(timer);
				message.complete ? resolve() : reject(new Error('Fresh-process reconciliation refused.'));
			});
			child.once('error', () => reject(new Error('Fresh process unavailable.')));
			child.send({ ...config, serverUrl: config.serverUrl.href });
		});
		await new Promise<void>(resolve =>
			child.exitCode !== null ? resolve() : child.once('exit', () => resolve())
		);
		assert(JSON.stringify(completions[1]) === previous, 'Durable completion changed on replay.');
		assert.equal(acknowledgements, ackBefore, 'Restart replay must not ACK/execute the command again.');
		assert.equal(events, eventsBefore, 'Restart replay must not emit execution progress.');
		if (completion.success) {
			const snapshots = JSON.parse(await run('/usr/local/bin/restic',
				['--no-cache', '-r', path.join(storage, current.payload.repository.path), 'snapshots', '--json'],
				undefined, { RESTIC_PASSWORD: repoPassword }));
			assert.equal(snapshots.length, 1, 'Completion replay must not create another snapshot.');
		}
		assert.equal(journal.filter(s => s.includes('database-dump-started')).length, before);
		assert.equal((await loadIdentity(dataDir)).completedCommands.length, 1);
		for (const value of forbidden)
			assert(
				!JSON.stringify({
					journal,
					records,
					completions: completions.map(({ leaseToken, ...safe }) => safe),
				}).includes(value)
			);
		records.push({
			scenario: fault,
			baseline,
			success: completion.success,
			stage: completion.failureStage,
			code: completion.failureCode,
			statusCalls,
			events,
			postDumpAttempts: applied,
			durationMs: Math.round(performance.now() - started),
		});
		originalInfo(JSON.stringify({ event: 'agent_post_dump_case', ...records.at(-1) }));
	}
	originalInfo(
		JSON.stringify({
			event: 'agent_post_dump_native',
			nodeVersion: process.version,
			mysqlVersion: version.trim(),
			baseline,
			cases: records,
		})
	);
} finally {
	console.info = originalInfo;
	console.error = originalError;
	server?.closeAllConnections();
	if (server) await new Promise<void>(r => server!.close(() => r()));
	for (const child of children) child.kill('SIGTERM');
	await fs.rm(root, { recursive: true, force: true });
}
