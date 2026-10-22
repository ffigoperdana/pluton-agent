// Synthetic loopback TCP SYN delay. Run only in a disposable, private network
// namespace with NET_ADMIN; no external host, DNS or enrollment token is used.
import assert from 'node:assert/strict';
import https from 'node:https';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { AgentTransport } from '../../agent/dist/transport.js';
import { createAgentConfig } from '../../agent/dist/config.js';

assert(fs.existsSync('/opt/pluton-disposable-ubuntu-test'));
assert.equal(process.getuid(), 0);
assert.equal(process.version, 'v22.18.0');
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'pluton-tcp-delay-'));
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
  '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
  '-keyout', scratch + '/key.pem', '-out', scratch + '/ca.pem'], { stdio: 'ignore' });
const ca = fs.readFileSync(scratch + '/ca.pem');
const tc = (...args) => execFileSync('tc', args, { stdio: 'pipe' });
try {
  for (const family of [4, 6]) {
    let requests = 0;
    const server = https.createServer({ key: fs.readFileSync(scratch + '/key.pem'), cert: ca }, (request, response) => {
      requests++; request.resume(); response.end('{"success":true,"result":{}}');
    });
    const host = family === 4 ? '127.0.0.1' : '::1';
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, host, resolve); });
    const port = server.address().port;
    const addresses = [{ address: host, family }, { address: family === 4 ? '::1' : '127.0.0.1', family: family === 4 ? 6 : 4 }];
    const lookup = (_hostname, options, callback) => {
      if (options.all) callback(null, addresses);
      else callback(null, addresses[0].address, addresses[0].family);
    };
    try {
      tc('qdisc', 'add', 'dev', 'lo', 'root', 'handle', '1:', 'prio');
      tc('qdisc', 'add', 'dev', 'lo', 'parent', '1:3', 'handle', '30:', 'netem', 'delay', '600ms');
      const ipv = family === 4 ? 'ip' : 'ip6';
      const protocol = family === 4 ? 'ip' : 'ipv6';
      const filter = ['filter', 'add', 'dev', 'lo', 'protocol', protocol, 'parent', '1:', 'prio', '3', 'u32'];
      if (family === 4) filter.push('match', 'ip', 'protocol', '6', '0xff');
      filter.push('match', ipv, 'dport', String(port), '0xffff', 'match', 'u8', '0x02', '0x12',
        'at', family === 4 ? '33' : '53', 'flowid', '1:3');
      tc(...filter);
      const request = (explicit) => new Promise((resolve, reject) => {
        const r = https.request({ hostname: 'localhost', port, path: '/api/agent/enroll', method: 'POST',
          ca, lookup, agent: false, ...(explicit ? { family } : { autoSelectFamily: true, autoSelectFamilyAttemptTimeout: 250 }) },
        (response) => { response.resume(); response.once('end', () => resolve(response.statusCode)); });
        const timer = setTimeout(() => r.destroy(new Error('synthetic request deadline')), 5000);
        r.once('close', () => clearTimeout(timer)); r.once('error', reject); r.end('{}');
      });
      await assert.rejects(request(false));
      assert.equal(requests, 0);
      assert.equal(await request(true), 200);
      const config = createAgentConfig({ serverUrl: `https://localhost:${port}`, caFile: scratch + '/ca.pem' });
      await new AgentTransport(config, 5000, undefined, { lookup }).post('/api/agent/enroll', '{}');
      assert.equal(requests, 2);
      console.log(`PASS IPv${family}: native 250ms autoselection loses a delayed viable SYN; explicit family and retained parallel verified connection succeed, one POST each`);
    } finally {
      try { tc('qdisc', 'del', 'dev', 'lo', 'root'); } catch { /* namespace is disposable; never modify a host qdisc */ }
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    }
  }
  console.log('LIMITATION: synthetic SYN timing reproduction, not evidence of the production routing cause or native VM acceptance');
} finally { fs.rmSync(scratch, { recursive: true, force: true }); }
