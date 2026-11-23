'use strict';

const { createRequire } = require('node:module');
const path = require('node:path');
const manifest = require('../package.json');
const { Denial } = require('./common.cjs');

const npm = createRequire(path.resolve(path.dirname(process.execPath), '../lib/node_modules/npm/package.json'));
const pinned = { ...manifest.dependencies, ...manifest.devDependencies };

// Kurulu proje paketlerini ya da dağıtımın npm ile sağladığı aynı sürümü kullanır.
function sigstore(name) {
  for (const load of [require, npm]) {
    try {
      if (load(name + '/package.json').version === pinned[name]) return load(name);
    } catch (error) {
      if (error.code !== 'MODULE_NOT_FOUND') throw error;
    }
  }
  throw new Denial('VERIFIER_UNAVAILABLE', 'Gereken Sigstore paketi bu sürümde bulunamadı: ' + name + '@' + pinned[name]);
}

module.exports = { sigstore };
