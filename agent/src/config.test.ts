import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { configFromEnvironment, createAgentConfig, parseAllowedRoots } from './config.js';

test('rejects insecure HTTP unless explicitly enabled', () => {
	assert.throws(() => createAgentConfig({ serverUrl: 'http://192.0.2.10:5173', allowInsecureHttp: false }), /HTTP is disabled/);
	assert.equal(createAgentConfig({ serverUrl: 'http://192.0.2.10:5173', allowInsecureHttp: true }).serverUrl.protocol, 'http:');
});

test('accepts HTTPS and parses generic allowed roots', () => {
	const config = createAgentConfig({ serverUrl: 'https://pluton.example.internal', allowedRoots: '/srv/example-app,\n/var/lib/example' });
	assert.equal(config.serverUrl.protocol, 'https:');
	assert.deepEqual(parseAllowedRoots('/srv/example-app,\n/var/lib/example'), ['/srv/example-app', '/var/lib/example']);
});

test('reads an absolute storage CA file and refuses relative or control-character paths', () => {
	const expected = path.resolve('/etc/pluton-agent/storage-ca.pem');
	assert.equal(createAgentConfig({ serverUrl: 'https://pluton.example.internal', storageCaFile: '/etc/pluton-agent/storage-ca.pem' }).storageCaFile, expected);
	assert.equal(createAgentConfig({ serverUrl: 'https://pluton.example.internal' }).storageCaFile, undefined);
	assert.equal(createAgentConfig({ serverUrl: 'https://pluton.example.internal', storageCaFile: '' }).storageCaFile, undefined);
	assert.throws(() => createAgentConfig({ serverUrl: 'https://pluton.example.internal', storageCaFile: 'storage-ca.pem' }), /PLUTON_AGENT_STORAGE_CA_FILE/);
	assert.throws(() => createAgentConfig({ serverUrl: 'https://pluton.example.internal', storageCaFile: '/etc/pluton-agent/ca\n.pem' }), /PLUTON_AGENT_STORAGE_CA_FILE/);
	assert.equal(configFromEnvironment({ PLUTON_SERVER_URL: 'https://pluton.example.internal', PLUTON_AGENT_STORAGE_CA_FILE: '/etc/pluton-agent/storage-ca.pem' }).storageCaFile, expected);
});
