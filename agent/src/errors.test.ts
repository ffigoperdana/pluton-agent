import assert from 'node:assert/strict';
import test from 'node:test';
import { AgentOperationError, atAgentStage, formatAgentFailure } from './errors.js';
import { SourcePolicyError } from './sourceAccessPolicy.js';
import { AgentNetworkError } from './network.js';
import { AgentHttpError } from './transport.js';

test('reports a lifecycle stage without including a sensitive upstream error message', async () => {
	const sensitiveValue = 'secret-value-that-must-not-be-logged';
	await assert.rejects(
		() => atAgentStage('poll', () => Promise.reject(new Error(`request failed: ${sensitiveValue}`))),
		error => {
			assert.ok(error instanceof AgentOperationError);
			const output = formatAgentFailure(error);
			assert.equal(output, 'poll failed: operation failed.');
			assert.equal(output.includes(sensitiveValue), false);
			return true;
		}
	);
});

test('preserves the safe command-verification diagnostic and its stage', () => {
	const output = formatAgentFailure(
		new AgentOperationError('verify-command', 'command lease has expired; check clock synchronization')
	);
	assert.equal(output, 'verify-command failed: command lease has expired; check clock synchronization.');
});

test('local policy refusal exposes only a bounded safe code, never injected path or credential text', () => {
	assert.equal(formatAgentFailure(new SourcePolicyError('source-policy-stale')), 'startup failed: source access refused (source-policy-stale).');
	const unsafe = formatAgentFailure(new SourcePolicyError('source-private/path?token=synthetic'));
	assert.equal(unsafe, 'startup failed: operation failed.');
});

test('network failure diagnostics expose fixed classifications only, never arbitrary error text or response bodies', () => {
	for (const code of ['DNS_FAILURE', 'DNS_TIMEOUT', 'CONNECT_TIMEOUT', 'TLS_VERIFICATION_FAILED', 'CONNECTION_INTERRUPTED',
		'REQUEST_TIMEOUT', 'INVALID_RESPONSE', 'RESPONSE_TOO_LARGE', 'ENROLLMENT_REJECTED'] as const) {
		const failure = new AgentNetworkError(code);
		failure.message = 'synthetic-token private-key Authorization request-body must-not-print';
		assert.ok(!formatAgentFailure(failure).includes('synthetic-token'));
		assert.notEqual(formatAgentFailure(failure), 'startup failed: operation failed.');
	}
	assert.equal(formatAgentFailure(new AgentHttpError(403, 'Authorization: synthetic-private')), 'startup failed: server returned HTTP 403.');
	assert.equal(formatAgentFailure(new AgentHttpError(NaN, 'synthetic-private')), 'startup failed: operation failed.');
	for (const unsafe of ['synthetic-private', '__proto__', 'constructor'])
		assert.equal(formatAgentFailure(new AgentNetworkError(unsafe as never)), 'startup failed: operation failed.');
});
