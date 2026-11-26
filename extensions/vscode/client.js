'use strict';
// Thin client for the OpenCobot daemon protocol (docs/IDE_API.md).
//
// Node stdlib only (net, fs, os, path) and NO `vscode` import, so
// this module is unit-tested in plain Node against a fake daemon
// (`node --test test/client.test.js`) and portable to any other
// IDE: port these ~150 lines, not the VS Code glue.
//
// The client NEVER calls a model, NEVER writes workspace files and
// NEVER talks to policyd. It frames requests, attaches the daemon
// token, and returns the daemon's reply.

const net = require('net');
const fs = require('fs');
const os = require('os');
const path = require('path');

// Default timeouts: plain ops are fast; an orchestrator run can
// take minutes (model calls), so it gets a long one. Never retry
// on timeout — a retry would start a second run server-side.
const DEFAULT_TIMEOUT_MS = 10_000;
const RUN_TIMEOUT_MS = 10 * 60 * 1000;

// Named-pipe address on Windows: \\.\pipe\opencobot-daemon
const DAEMON_PIPE = '\\\\.\\pipe\\opencobot-daemon';

function defaultStateDir() {
  return process.env.OPENCOBOT_STATE
    || path.join(os.homedir(), '.opencobot');
}

function daemonAddress(stateDir) {
  if (process.platform === 'win32') {
    return DAEMON_PIPE;
  }
  return path.join(stateDir, 'daemon.sock');
}

function readAuthToken(stateDir) {
  const tokenPath = path.join(stateDir, 'daemon.auth');
  try {
    return fs.readFileSync(tokenPath, 'utf8').trim();
  } catch (err) {
    throw new Error(
      `daemon token not found: ${tokenPath} — is the daemon running? (${err.code || err.message})`);
  }
}

/**
 * Send one request, await one reply. Resolves with the reply object.
 * Rejects on connect error, timeout, or an unparseable reply.
 * The socket is closed after the first reply line.
 */
function request(stateDir, req, { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  return new Promise((resolve, reject) => {
    let token;
    try {
      token = readAuthToken(stateDir);
    } catch (err) {
      reject(err);
      return;
    }
    const address = daemonAddress(stateDir);
    const socket = net.createConnection(address);
    let settled = false;
    let buffer = '';
    const done = (err, value) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      try {
        socket.destroy();
      } catch (ignored) {
        // Already gone; nothing to clean up.
      }
      if (err) {
        reject(err);
      } else {
        resolve(value);
      }
    };
    const timer = setTimeout(() => {
      done(new Error(
        `daemon request timed out after ${timeoutMs}ms (${req.op}) — ` +
        'the daemon may still be working; check orchestrator_status'));
    }, timeoutMs);
    socket.on('connect', () => {
      socket.write(JSON.stringify({ auth: token, ...req }) + '\n');
    });
    socket.on('data', (chunk) => {
      buffer += chunk.toString('utf8');
      const newline = buffer.indexOf('\n');
      if (newline === -1) {
        return;
      }
      const line = buffer.slice(0, newline);
      try {
        done(null, JSON.parse(line));
      } catch (err) {
        done(new Error(`daemon sent an unparseable reply: ${err.message}`));
      }
    });
    socket.on('error', (err) => {
      done(new Error(`cannot reach the daemon at ${address}: ${err.message}`));
    });
  });
}

function daemonStatus(stateDir) {
  return request(stateDir, { op: 'status' });
}

function orchestratorRun(stateDir, { task, token, sensitivity,
  workspace, architect, workers, project }) {
  if (typeof task !== 'string' || !task.trim()) {
    return Promise.reject(new Error('orchestratorRun needs task: <string>'));
  }
  const req = { op: 'orchestrator_run', task };
  if (token !== undefined) {
    req.token = token;
  }
  if (sensitivity !== undefined) {
    req.sensitivity = sensitivity;
  }
  if (workspace !== undefined) {
    req.workspace = workspace;
  }
  if (architect !== undefined) {
    req.architect = architect;
  }
  if (workers !== undefined) {
    req.workers = workers;
  }
  if (project !== undefined) {
    req.project = project;
  }
  return request(stateDir, req, { timeoutMs: RUN_TIMEOUT_MS });
}

function orchestratorStatus(stateDir, { runId, project }) {
  const req = { op: 'orchestrator_status' };
  if (runId !== undefined) {
    req.run_id = runId;
  }
  if (project !== undefined) {
    req.project = project;
  }
  return request(stateDir, req);
}

function retryQueued(stateDir, { runId, token, sensitivity,
  workspace, architect, workers, project }) {
  if (typeof runId !== 'string' || !runId) {
    return Promise.reject(new Error('retryQueued needs runId: <string>'));
  }
  const req = { op: 'orchestrator_retry', run_id: runId };
  if (token !== undefined) {
    req.token = token;
  }
  if (sensitivity !== undefined) {
    req.sensitivity = sensitivity;
  }
  if (workspace !== undefined) {
    req.workspace = workspace;
  }
  if (architect !== undefined) {
    req.architect = architect;
  }
  if (workers !== undefined) {
    req.workers = workers;
  }
  if (project !== undefined) {
    req.project = project;
  }
  return request(stateDir, req, { timeoutMs: RUN_TIMEOUT_MS });
}

module.exports = {
  defaultStateDir,
  daemonAddress,
  readAuthToken,
  request,
  daemonStatus,
  orchestratorRun,
  orchestratorStatus,
  retryQueued,
  DEFAULT_TIMEOUT_MS,
  RUN_TIMEOUT_MS,
};
