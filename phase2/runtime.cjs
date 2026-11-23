'use strict';

const { fork } = require('node:child_process');
const { randomUUID } = require('node:crypto');
const path = require('node:path');
const { performance } = require('node:perf_hooks');
const { check, Failure, endpoint, request, bounded } = require('./http.cjs');

const readinessMs = 350;

function identity(instance) {
  if (!instance) return null;
  return { role: instance.role, instanceId: instance.id, pid: instance.child.pid, image: instance.image, digest: instance.digest };
}

function matches(instance, body) {
  return body?.pid === instance.child.pid && body.instanceId === instance.id && body.digest === instance.digest;
}

async function start(scope, role, decision, manifest, { health = 'ready', readOnlyOnSecond = false } = {}) {
  check(decision.decision === 'allow' && decision.approvedImage && decision.imageSignatureVerified &&
    decision.provenanceSignatureVerified, 'LAUNCH_NOT_ADMITTED');
  const id = randomUUID();
  const socket = path.join(scope.dir, role + '.sock');
  const child = fork(path.join(__dirname, 'service.cjs'), [], {
    cwd: scope.dir, env: {}, execArgv: [], stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
  });
  const instance = { role, id, socket, child, image: decision.approvedImage, digest: decision.digest, ended: false };
  instance.done = new Promise(resolve => child.once('close', (code, signal) => {
    instance.ended = true;
    resolve({ code, signal });
  }));
  scope.children.push(instance);
  const boot = new Promise((resolve, reject) => {
    child.once('error', () => reject(new Failure('PROCESS_START_FAILED')));
    instance.done.then(() => reject(new Failure('PROCESS_EXITED')));
    child.once('message', msg => {
      if (msg?.type === 'listening' && msg.instanceId === id && msg.pid === child.pid) resolve();
      else reject(new Failure('PROCESS_START_FAILED'));
    });
    child.send({ socket, instanceId: id, database: scope.database, manifest: manifest.toString('base64'), health, readOnlyOnSecond },
      error => { if (error) reject(new Failure('PROCESS_START_FAILED')); });
  });
  await bounded(boot, 4000, 'PROCESS_START_TIMEOUT');
  return instance;
}

async function stop(instance) {
  if (!instance.ended) {
    instance.child.kill('SIGTERM');
    try { await bounded(instance.done, 1000, 'PROCESS_STOP_TIMEOUT'); }
    catch {
      if (!instance.ended) instance.child.kill('SIGKILL');
      await bounded(instance.done, 1500, 'PROCESS_STOP_TIMEOUT');
    }
  }
}

async function probe(instance, socket = instance.socket, source = instance.role, requireDirect = true) {
  const then = performance.now();
  const result = { source, expected: identity(instance), deadlineMs: readinessMs, http: null, observed: null };
  try {
    const { status, body } = await request(socket, '/ready', { deadline: readinessMs });
    result.http = status;
    result.observed = { instanceId: body?.instanceId ?? null, pid: body?.pid ?? null, digest: body?.digest ?? null };
    if ((requireDirect && socket !== instance.socket) || body?.instanceId !== instance.id || body?.pid !== instance.child.pid) {
      result.reason = 'WRONG_INSTANCE';
    } else if (body.digest !== instance.digest) {
      result.reason = 'WRONG_DIGEST';
    } else if (status !== 200 || body.ready !== true) {
      result.reason = status === 503 ? 'HTTP_503' : 'NOT_READY';
    } else {
      result.reason = 'READY';
    }
  } catch (error) {
    result.reason = error.code === 'DEADLINE_EXCEEDED' ? 'READINESS_TIMEOUT' : 'CONNECTION_FAILED';
    result.transportError = error.code || 'INVALID_RESPONSE';
  }
  result.elapsedMs = Math.round(performance.now() - then);
  return result;
}

async function startRouter(scope) {
  const router = { active: null, socket: path.join(scope.dir, 'shared.sock') };
  router.server = endpoint(async (method, route, body) => {
    const selected = router.active;
    if (!selected) return { status: 503, body: { error: 'TRAFFIC_HELD' } };
    try {
      const reply = await request(selected.socket, route, { method, body, deadline: 800 });
      if (router.active !== selected || !matches(selected, reply.body)) throw new Failure('ROUTE_IDENTITY');
      return reply;
    } catch {
      return { status: 502, body: { error: 'BACKEND_UNAVAILABLE' } };
    }
  });
  scope.router = router;
  const listen = new Promise((resolve, reject) => {
    router.server.once('error', reject);
    router.server.listen(router.socket, resolve);
  });
  await bounded(listen, 2000, 'ROUTER_START_TIMEOUT');
  return router;
}

async function shutdown(scope) {
  if (scope.router) scope.router.active = null;
  const work = scope.children.map(stop);
  if (scope.router?.server.listening) {
    const server = scope.router.server;
    const closed = new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    server.closeAllConnections();
    work.push(bounded(closed, 1500, 'ROUTER_STOP_TIMEOUT'));
  }
  const results = await Promise.allSettled(work);
  check(results.every(r => r.status === 'fulfilled'), 'CLEANUP_FAILED');
}

module.exports = { start, stop, probe, startRouter, shutdown, identity, matches };
