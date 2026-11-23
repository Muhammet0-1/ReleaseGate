'use strict';

const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const assert = require('node:assert/strict');

const policy = require('./policy/test.json');
const variants = require('./test/variants.json');
const original = path.join(__dirname, 'fixtures/candidate');
const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'parcel-gate-demo-'));
const candidate = path.join(workspace, 'candidate');
const approved = policy.imageRepository + '@' + policy.approvedDigest;

function gate(image, reason) {
  const run = spawnSync(process.execPath, [path.join(__dirname, 'gate.cjs'), image, 'test', candidate], { encoding: 'utf8' });
  assert.equal(run.status, reason === 'APPROVED' ? 0 : 1);
  const record = JSON.parse(run.stdout);
  assert.equal(record.reason, reason);
  console.log(JSON.stringify(record));
  return run.stdout;
}

function evidence(file, value) {
  fs.writeFileSync(path.join(candidate, file), JSON.stringify(value));
}

try {
  fs.cpSync(original, candidate, { recursive: true });
  const decision = gate(approved, 'APPROVED');
  evidence('provenance.sigstore.json', variants.provenance.wrongCommit);
  gate(approved, 'COMMIT_NOT_APPROVED');

  fs.copyFileSync(path.join(candidate, 'alternate-index.json'), path.join(candidate, 'oci/index.json'));
  const other = JSON.parse(fs.readFileSync(path.join(candidate, 'oci/index.json'))).manifests[0].digest;
  evidence('image.sigstore.json', variants.alternate.image);
  evidence('provenance.sigstore.json', variants.alternate.provenance);
  gate(policy.imageRepository + '@' + other, 'DIGEST_NOT_APPROVED');

  const next = spawnSync(process.execPath, [path.join(__dirname, 'receive.cjs'), candidate], { input: decision, encoding: 'utf8' });
  assert.equal(next.status, 0);
  assert.equal(JSON.parse(next.stdout).receivedImage, approved);
  process.stdout.write(next.stdout);
} finally {
  fs.rmSync(workspace, { recursive: true, force: true });
}
