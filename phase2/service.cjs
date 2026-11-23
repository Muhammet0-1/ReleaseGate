'use strict';

const fs = require('node:fs');
const { DatabaseSync } = require('node:sqlite');
const { digest } = require('../lib/common.cjs');
const { endpoint } = require('./http.cjs');

let db, server;
let stopping = false;
function stop(code = 0) {
  if (stopping) return;
  stopping = true;
  try {
    server?.close();
    server?.closeAllConnections();
    db?.close();
    process.exitCode = code;
  } catch {
    process.exitCode = 1;
  }
  if (process.connected) process.disconnect();
}
process.once('disconnect', () => stop());
process.once('SIGTERM', () => stop());

process.once('message', config => {
  try {
    // Denetleyici beklenen digest'i göndermez. Bu süreç seçilen manifest baytlarını özetler.
    const identity = { instanceId: config.instanceId, pid: process.pid, digest: digest(Buffer.from(config.manifest, 'base64')) };
    if (!fs.statSync(config.database).isFile()) throw new Error('Veri dosyası eksik.');
    db = new DatabaseSync(config.database, { timeout: 500 });
    const store = db.prepare('SELECT id FROM store').get().id;
    const insert = db.prepare('INSERT INTO records (id, value) VALUES (?, ?)');
    const get = db.prepare('SELECT id, value FROM records WHERE id = ?');
    const reply = (status, fields) => ({ status, body: { ...identity, store, ...fields } });
    server = endpoint((method, route, data) => {
      if (method === 'GET' && route === '/ready') {
        if (config.health === 'timeout') return;
        const ready = config.health !== '503';
        return reply(ready ? 200 : 503, { ready });
      }
      if (method === 'POST' && route === '/records') {
        if (!data || !/^[a-z0-9-]{1,48}$/.test(data.id) || typeof data.value !== 'string' || data.value.length > 160) {
          return reply(400, { error: 'INVALID_RECORD' });
        }
        try {
          if (config.readOnlyOnSecond && data.id === 'during-staging') db.exec('PRAGMA query_only = ON');
          insert.run(data.id, data.value);
          return reply(201, { record: get.get(data.id) });
        } catch {
          return reply(500, { error: 'DB_WRITE_FAILED' });
        }
      }
      const match = /^\/records\/([a-z0-9-]{1,48})$/.exec(route);
      if (method === 'GET' && match) {
        const record = get.get(match[1]);
        return reply(record ? 200 : 404, { record: record || null });
      }
      return reply(404, { error: 'NOT_FOUND' });
    });
    server.once('error', () => {
      if (process.connected) process.send({ type: 'startup-error' });
      stop(1);
    });
    server.listen(config.socket, () => {
      if (process.connected) process.send({ type: 'listening', instanceId: identity.instanceId, pid: process.pid });
    });
  } catch {
    if (process.connected) process.send({ type: 'startup-error' });
    stop(1);
  }
});
