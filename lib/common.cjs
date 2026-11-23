'use strict';

const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

class Denial extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

function requireCheck(ok, code, message) {
  if (!ok) throw new Denial(code, message);
}

function digest(bytes) {
  return 'sha256:' + createHash('sha256').update(bytes).digest('hex');
}

const digestPattern = /^sha256:[0-9a-f]{64}$/;
const imagePattern = /^([a-z0-9]+(?:[.-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)+)@(sha256:[0-9a-f]{64})$/;

function parseImage(value) {
  const match = typeof value === 'string' && imagePattern.exec(value);
  requireCheck(match && match[0] === value, 'IMAGE_REFERENCE', 'İmaj adı tam bir repository@sha256 referansı olmalı.');
  return { repository: match[1], digest: match[2] };
}

// Linux üzerinde önce açılan nesnenin konumunu denetle, sonra aynı fd üzerinden oku.
function readFileBelow(root, relative, limit) {
  const base = fs.realpathSync(root);
  const target = path.join(base, relative);
  const flags = fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK;
  const fd = fs.openSync(target, flags);
  try {
    const stat = fs.fstatSync(fd);
    if (fs.realpathSync('/proc/self/fd/' + fd) !== target ||
        !stat.isFile() || stat.size < 1 || stat.size > limit) {
      throw new Error('Geçersiz yerel dosya.');
    }
    const bytes = Buffer.alloc(stat.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (!count) throw new Error('Eksik dosya.');
      offset += count;
    }
    if (fs.fstatSync(fd).size !== bytes.length) throw new Error('Dosya boyutu değişti.');
    return bytes;
  } finally {
    fs.closeSync(fd);
  }
}

const utf8 = new TextDecoder('utf-8', { fatal: true });
function parseJSON(bytes) {
  return JSON.parse(utf8.decode(bytes));
}

function exactKeys(value, keys) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  return Object.keys(value).length === keys.length && keys.every(k => Object.hasOwn(value, k));
}

module.exports = { Denial, requireCheck, digest, digestPattern, parseImage, readFileBelow, parseJSON, exactKeys };
