'use strict';
// Tests for extensions/vscode/client.js — the thin daemon client.
//
// Runs in plain Node against a fake daemon (a Unix-socket server
// that records requests and answers canned JSON lines). No VS Code,
// no real daemon, no network. Run: `node --test test/client.test.js`
// from extensions/vscode/.

const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const client = require('../client');

function tmpStateDir(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'opencobot-ide-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.writeFileSync(path.join(dir, 'daemon.auth'), 'test-token\n');
  return dir;
}

// A fake daemon: records each request line, replies with whatever
// `reply` returns (a dict, a raw string, or null for silence).
function fakeDaemon(t, stateDir, reply) {
  const sock = path.join(stateDir, 'daemon.sock');
  const seen = [];
  const server = net.createServer((conn) => {
    let buffer = '';
    conn.on('data', (chunk) => {
      buffer += chunk.toString('utf8');
      let idx;
      while ((idx = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, idx);
        buffer = buffer.slice(idx + 1);
        if (!line) {
          continue;
        }
        seen.push(JSON.parse(line));
        const out = typeof reply === 'function'
          ? reply(JSON.parse(line), seen.length)
          : reply;
        if (out === null || out === undefined) {
          continue; // stay silent (timeout test)
        }
        conn.write(typeof out === 'string' ? out + '\n' : JSON.stringify(out) + '\n');
      }
    });
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(sock, () => {
      t.after(() => new Promise((done) => server.close(done)));
      resolve({ server, seen, sock });
    });
  });
}

test('request sends one JSON line with auth and parses the reply', async (t) => {
  const dir = tmpStateDir(t);
  const { seen } = await fakeDaemon(t, dir, { ok: true, tools: 23 });
  const reply = await client.request(dir, { op: 'status' });
  assert.deepEqual(reply, { ok: true, tools: 23 });
  assert.equal(seen.length, 1);
  assert.equal(seen[0].auth, 'test-token');
  assert.equal(seen[0].op, 'status');
});

test('daemonStatus returns the daemon reply', async (t) => {
  const dir = tmpStateDir(t);
  await fakeDaemon(t, dir, { ok: true, tools: 23, killed: false,
    policyd_reachable: true, readonly: false });
  const reply = await client.daemonStatus(dir);
  assert.equal(reply.ok, true);
  assert.equal(reply.tools, 23);
});

test('orchestratorRun sends task, workspace, token, defaults public', async (t) => {
  const dir = tmpStateDir(t);
  const { seen } = await fakeDaemon(t, dir, {
    ok: true, run: { ok: true, run_id: 'abc123', integrated: [] },
  });
  const reply = await client.orchestratorRun(dir, {
    task: 'do the thing', workspace: '/home/u/proj',
    token: { folders: ['/home/u/proj'] },
  });
  assert.equal(reply.run.run_id, 'abc123');
  assert.equal(seen[0].op, 'orchestrator_run');
  assert.equal(seen[0].task, 'do the thing');
  assert.equal(seen[0].workspace, '/home/u/proj');
  assert.deepEqual(seen[0].token, { folders: ['/home/u/proj'] });
  assert.equal(seen[0].sensitivity, undefined); // server default
});

test('orchestratorRun rejects an empty task without touching the daemon', async (t) => {
  const dir = tmpStateDir(t);
  const { seen } = await fakeDaemon(t, dir, { ok: true });
  await assert.rejects(client.orchestratorRun(dir, { task: '  ' }), /needs task/);
  assert.equal(seen.length, 0);
});

test('orchestratorStatus sends run_id or project', async (t) => {
  const dir = tmpStateDir(t);
  const { seen } = await fakeDaemon(t, dir, (req) => ({
    ok: true, run: { run_id: req.run_id || 'last', task: 'x' },
  }));
  const byId = await client.orchestratorStatus(dir, { runId: 'abc123' });
  assert.equal(byId.run.run_id, 'abc123');
  const byProject = await client.orchestratorStatus(dir, { project: 'proj' });
  assert.equal(byProject.run.run_id, 'last');
  assert.equal(seen[0].run_id, 'abc123');
  assert.equal(seen[1].project, 'proj');
});

test('retryQueued sends run_id and the token', async (t) => {
  const dir = tmpStateDir(t);
  const { seen } = await fakeDaemon(t, dir, {
    ok: true, retry: { ok: true, retried: ['a'], still_queued: [] },
  });
  const reply = await client.retryQueued(dir, {
    runId: 'abc123', token: { folders: ['/home/u/proj'] },
    workspace: '/home/u/proj',
  });
  assert.equal(reply.retry.ok, true);
  assert.equal(seen[0].op, 'orchestrator_retry');
  assert.equal(seen[0].run_id, 'abc123');
  await assert.rejects(client.retryQueued(dir, { runId: '' }), /needs runId/);
});

test('missing daemon socket rejects with the address', async (t) => {
  const dir = tmpStateDir(t); // no server listening
  await assert.rejects(client.daemonStatus(dir), /daemon\.sock/);
});

test('missing daemon.auth rejects before connecting', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'opencobot-ide-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  await assert.rejects(client.daemonStatus(dir), /daemon token not found/);
});

test('unparseable reply rejects', async (t) => {
  const dir = tmpStateDir(t);
  await fakeDaemon(t, dir, 'this is not json');
  await assert.rejects(client.daemonStatus(dir), /unparseable reply/);
});

test('silent daemon rejects on timeout', async (t) => {
  const dir = tmpStateDir(t);
  await fakeDaemon(t, dir, null); // never replies
  await assert.rejects(
    client.request(dir, { op: 'status' }, { timeoutMs: 50 }),
    /timed out after 50ms/);
});

test('readAuthToken trims whitespace; daemonAddress is the socket path', (t) => {
  const dir = tmpStateDir(t);
  assert.equal(client.readAuthToken(dir), 'test-token');
  assert.equal(client.daemonAddress(dir), path.join(dir, 'daemon.sock'));
  assert.equal(client.defaultStateDir(),
    process.env.OPENCOBOT_STATE || path.join(os.homedir(), '.opencobot'));
});
