'use strict';

const http = require('node:http');

class Failure extends Error {
  constructor(code, message = code) {
    super(message);
    this.code = code;
  }
}

function check(ok, code) {
  if (!ok) throw new Failure(code);
}

const maxBody = 8192;

async function readBody(stream) {
  const parts = [];
  let size = 0;
  for await (const part of stream) {
    size += part.length;
    check(size <= maxBody, 'BODY_TOO_LARGE');
    parts.push(part);
  }
  return size ? JSON.parse(Buffer.concat(parts).toString('utf8')) : null;
}

function endpoint(handler) {
  return http.createServer({ requestTimeout: 2000 }, async (req, res) => {
    let reply;
    try {
      reply = await handler(req.method, req.url, await readBody(req));
      if (!reply) return; // Zaman aşımı senaryosu başlık da göndermeden bekler.
    } catch {
      reply = { status: 500, body: { error: 'REQUEST_FAILED' } };
    }
    if (!res.destroyed) {
      res.writeHead(reply.status, { 'content-type': 'application/json', connection: 'close' });
      res.end(JSON.stringify(reply.body));
    }
  });
}

// Zaman sınırı bağlanma, başlıklar ve yanıt gövdesinin tamamı için ortaktır.
function request(socketPath, route, { method = 'GET', body, deadline = 1200 } = {}) {
  return new Promise((resolve, reject) => {
    let timer;
    const req = http.request({ socketPath, path: route, method, agent: false, headers: { connection: 'close' } }, async res => {
      try {
        const value = await readBody(res);
        resolve({ status: res.statusCode, body: value });
      } catch (error) {
        reject(error);
      } finally {
        clearTimeout(timer);
      }
    });
    timer = setTimeout(() => {
      reject(new Failure('DEADLINE_EXCEEDED'));
      req.destroy();
    }, deadline);
    req.once('error', error => {
      clearTimeout(timer);
      reject(error);
    });
    req.end(body == null ? undefined : JSON.stringify(body));
  });
}

function bounded(operation, ms, code) {
  let timer;
  const timeout = new Promise((_, reject) => { timer = setTimeout(() => reject(new Failure(code)), ms); });
  return Promise.race([operation, timeout]).finally(() => clearTimeout(timer));
}

module.exports = { check, Failure, endpoint, request, bounded };
