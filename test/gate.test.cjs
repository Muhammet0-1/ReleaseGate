'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const { test } = require('node:test');
const { decide } = require('../gate.cjs');
const policy = require('../policy/test.json');
const variants = require('./variants.json');

const project = path.resolve(__dirname, '..');
const fixture = path.join(project, 'fixtures/candidate');
const image = policy.imageRepository + '@' + policy.approvedDigest;
const json = file => JSON.parse(fs.readFileSync(file));
const write = (file, value) => fs.writeFileSync(file, JSON.stringify(value));
const hash = file => 'sha256:' + createHash('sha256').update(fs.readFileSync(file)).digest('hex');

function workspace(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'parcel-gate-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const candidate = path.join(root, 'candidate');
  fs.cpSync(fixture, candidate, { recursive: true });
  return candidate;
}

function run(tool, args, input) {
  const executable = tool === 'ci.sh' ? 'sh' : process.execPath;
  const result = spawnSync(executable, [path.join(project, tool), ...args], { encoding: 'utf8', input });
  assert.ifError(result.error);
  return result;
}

function denied(result, reason, signatures = [true, true]) {
  assert.equal(result.status, 1, result.stdout + result.stderr);
  const records = result.stdout.trim().split('\n').map(line => JSON.parse(line));
  assert.equal(records.length, 1, 'Retten sonra teslim süreci çalışmamalı.');
  const d = records[0];
  assert.equal(d.decision, 'deny');
  assert.equal(d.reason, reason);
  assert.equal(d.approvedImage, null);
  assert.equal(d.policyVersion, 'test-v1');
  assert.deepEqual([d.imageSignatureVerified, d.provenanceSignatureVerified], signatures);
  return d;
}

function retag(candidate) {
  const index = path.join(candidate, 'oci/index.json');
  const before = json(index).manifests[0];
  fs.copyFileSync(path.join(candidate, 'alternate-index.json'), index);
  const after = json(index).manifests[0];
  assert.equal(before.annotations['org.opencontainers.image.ref.name'], 'candidate');
  assert.deepEqual(after.annotations, before.annotations);
  assert.notEqual(after.digest, before.digest);
  return after.digest;
}

test('onaylı imaj iki gerçek imzayla geçer ve CI aynı digest’i diğer sürece teslim eder', () => {
  const result = run('ci.sh', [image, 'test', fixture]);
  assert.equal(result.status, 0, result.stderr + result.stdout);
  const [d, handoff] = result.stdout.trim().split('\n').map(line => JSON.parse(line));
  assert.equal(d.decision, 'allow');
  assert.equal(d.reason, 'APPROVED');
  assert.equal(d.environment, 'test');
  assert.equal(d.policyVersion, 'test-v1');
  assert.equal(d.policySha256, hash(path.join(project, 'policy/test.json')));
  assert.equal(d.imageBundleSha256, hash(path.join(fixture, 'image.sigstore.json')));
  assert.equal(d.provenanceBundleSha256, hash(path.join(fixture, 'provenance.sigstore.json')));
  assert.equal(d.verifiedWorkflow, policy.workflow);
  assert.equal(d.imageSignatureVerified && d.provenanceSignatureVerified, true);
  assert.equal(d.approvedImage, image);
  assert.equal(d.digest, hash(path.join(fixture, 'oci/blobs/sha256', policy.approvedDigest.slice(7))));
  assert.deepEqual(handoff, { stage: 'dry-run', environment: 'test', receivedImage: image, digest: d.digest });
});

test('sabit girdilerle karar kaydı bayt düzeyinde tekrar üretilebilir', () => {
  const args = [image, 'test', fixture];
  const first = run('gate.cjs', args);
  const second = run('gate.cjs', args);
  assert.equal(first.status, 0);
  assert.equal(second.status, 0);
  assert.equal(first.stdout, second.stdout);
});

test('aynı etiketin iki geçerli imzalı farklı imajı onaylı digest ile uyuşmaz', t => {
  const candidate = workspace(t);
  const alternate = retag(candidate);
  write(path.join(candidate, 'image.sigstore.json'), variants.alternate.image);
  write(path.join(candidate, 'provenance.sigstore.json'), variants.alternate.provenance);
  const d = denied(run('ci.sh', [policy.imageRepository + '@' + alternate, 'test', candidate]), 'DIGEST_NOT_APPROVED');
  assert.equal(d.digest, alternate);
});

test('etiket karar sonrasında taşınsa da tüketici önceki onaylı manifesti açar', t => {
  const candidate = workspace(t);
  const gate = run('gate.cjs', [image, 'test', candidate]);
  assert.equal(gate.status, 0);
  retag(candidate);
  const next = run('receive.cjs', [candidate], gate.stdout);
  assert.equal(next.status, 0, next.stderr);
  assert.equal(JSON.parse(next.stdout).receivedImage, image);
});

test('onaylı içerik karar sonrasında kaybolursa tüketici diğer imaja geçmez', t => {
  const candidate = workspace(t);
  const gate = run('gate.cjs', [image, 'test', candidate]);
  assert.equal(gate.status, 0);
  retag(candidate);
  fs.unlinkSync(path.join(candidate, 'oci/blobs/sha256', policy.approvedDigest.slice(7)));
  const next = run('receive.cjs', [candidate], gate.stdout);
  assert.equal(next.status, 1);
  assert.equal(next.stdout, '');
  assert.equal(JSON.parse(next.stderr).reason, 'OCI_UNREADABLE');
});

test('istenen hedef ortam yanlışsa iki imza doğrulansa da CI durur', () => {
  denied(run('ci.sh', [image, 'prod', fixture]), 'TARGET_ENVIRONMENT');
});

const policyCases = [
  ['wrongCommit', 'COMMIT_NOT_APPROVED'], ['wrongWorkflow', 'WORKFLOW_ID'],
  ['wrongBuilder', 'BUILDER_ID'], ['wrongRepository', 'SOURCE_REPOSITORY'],
  ['differentMaterial', 'SOURCE_MATERIAL'], ['wrongEnvironment', 'BUILD_ENVIRONMENT'],
  ['differentSubject', 'SUBJECT_MISMATCH'], ['differentSubjectName', 'SUBJECT_MISMATCH'],
  ['extraSubject', 'SUBJECT_MISMATCH'], ['wrongBuildType', 'BUILD_TYPE'],
  ['extraInput', 'BUILD_INPUTS'], ['missingCommit', 'COMMIT_NOT_APPROVED'],
  ['otherPredicate', 'STATEMENT_TYPE'], ['invalidJson', 'STATEMENT_INVALID'],
];
for (const [key, reason] of policyCases) {
  test('imzası geçerli köken beyanı: ' + key + ' → ' + reason, t => {
    const candidate = workspace(t);
    write(path.join(candidate, 'provenance.sigstore.json'), variants.provenance[key]);
    denied(run('gate.cjs', [image, 'test', candidate]), reason);
  });
}

test('kimlik metni aynı olsa bile farklı iş akışı anahtarı reddedilir', t => {
  const candidate = workspace(t);
  write(path.join(candidate, 'provenance.sigstore.json'), variants.provenance.foreignKey);
  denied(run('ci.sh', [image, 'test', candidate]), 'PROVENANCE_SIGNATURE', [true, false]);
});

test('güvenilmeyen yayıncı anahtarının geçerli imzası reddedilir', t => {
  const candidate = workspace(t);
  write(path.join(candidate, 'image.sigstore.json'), variants.foreignPublisher);
  denied(run('ci.sh', [image, 'test', candidate]), 'IMAGE_SIGNATURE', [false, false]);
});

test('imzalı farklı DSSE medya türü reddedilir', t => {
  const candidate = workspace(t);
  write(path.join(candidate, 'provenance.sigstore.json'), variants.provenance.otherMediaType);
  denied(run('gate.cjs', [image, 'test', candidate]), 'PROVENANCE_TYPE', [true, false]);
});

for (const [file, code, flags] of [
  ['image.sigstore.json', 'IMAGE_SIGNATURE', [false, false]],
  ['provenance.sigstore.json', 'PROVENANCE_SIGNATURE', [true, false]],
]) {
  for (const failure of ['eksik', 'bozuk JSON', 'değiştirilmiş imza']) {
    test(file + ' / ' + failure + ' teslimi durdurur', t => {
      const candidate = workspace(t);
      const target = path.join(candidate, file);
      if (failure === 'eksik') fs.unlinkSync(target);
      if (failure === 'bozuk JSON') fs.writeFileSync(target, '{"verified":true');
      if (failure === 'değiştirilmiş imza') {
        const b = json(target);
        const entry = b.messageSignature || b.dsseEnvelope.signatures[0];
        const field = b.messageSignature ? 'signature' : 'sig';
        const bytes = Buffer.from(entry[field], 'base64');
        bytes[bytes.length - 1] ^= 1;
        entry[field] = bytes.toString('base64');
        write(target, b);
      }
      denied(run('ci.sh', [image, 'test', candidate]), code, flags);
    });
  }
}

test('iyi beyanla değiştirilmiş onaylı commit, eski DSSE imzasıyla doğrulanmaz', t => {
  const candidate = workspace(t);
  const b = structuredClone(variants.provenance.wrongCommit);
  b.dsseEnvelope.payload = json(path.join(fixture, 'provenance.sigstore.json')).dsseEnvelope.payload;
  write(path.join(candidate, 'provenance.sigstore.json'), b);
  denied(run('gate.cjs', [image, 'test', candidate]), 'PROVENANCE_SIGNATURE', [true, false]);
});

test('ham imza paketinin bildirdiği özet gerçek manifesto özetiyle uyuşmalı', t => {
  const candidate = workspace(t);
  const file = path.join(candidate, 'image.sigstore.json');
  const b = json(file);
  b.messageSignature.messageDigest.digest = Buffer.alloc(32).toString('base64');
  write(file, b);
  denied(run('gate.cjs', [image, 'test', candidate]), 'IMAGE_SIGNATURE', [false, false]);
});

test('adayın metadata veya politika kopyası onay kararını değiştiremez', t => {
  const candidate = workspace(t);
  fs.mkdirSync(path.join(candidate, 'policy'));
  write(path.join(candidate, 'policy/test.json'), { ...policy, approvedCommit: 'a'.repeat(40) });
  write(path.join(candidate, 'provenance.sigstore.json'), variants.provenance.wrongCommit);
  denied(run('gate.cjs', [image, 'test', candidate]), 'COMMIT_NOT_APPROVED');
});

test('mutable etiket ve tag@digest biçimleri kapıya kabul edilmez', () => {
  for (const ref of [policy.imageRepository + ':candidate', policy.imageRepository + ':candidate@' + policy.approvedDigest]) {
    const d = denied(run('ci.sh', [ref, 'test', fixture]), 'IMAGE_REFERENCE', [false, false]);
    assert.equal(d.digest, null);
  }
});

test('farklı OCI deposu aynı manifest ve imzalarla kullanılamaz', () => {
  denied(run('gate.cjs', ['registry.example.invalid/workshop/another@' + policy.approvedDigest, 'test', fixture]), 'IMAGE_REPOSITORY');
});

for (const part of ['manifest', 'config', 'layer']) {
  test(part + ' baytları değişince yerel blob bütünlüğü reddedilir', t => {
    const candidate = workspace(t);
    const blobs = path.join(candidate, 'oci/blobs/sha256');
    const manifest = json(path.join(blobs, policy.approvedDigest.slice(7)));
    const id = { manifest: policy.approvedDigest, config: manifest.config.digest, layer: manifest.layers[0].digest }[part];
    fs.appendFileSync(path.join(blobs, id.slice(7)), '\n');
    denied(run('ci.sh', [image, 'test', candidate]), 'OCI_DIGEST', [false, false]);
  });
}

test('eksik politika için adayın digest’i kaydedilir ve izin verilmez', t => {
  const candidate = workspace(t);
  const r = decide([image, 'test', candidate], path.dirname(candidate));
  assert.equal(r.reason, 'POLICY_INVALID');
  assert.equal(r.decision, 'deny');
  assert.equal(r.digest, policy.approvedDigest);
  assert.equal(r.policyVersion, null);
  assert.equal(r.approvedImage, null);
});

test('eksik onay veya aynı anahtara indirgenen roller geçersiz politikadır', t => {
  const candidate = workspace(t);
  const root = path.dirname(candidate);
  const missing = { ...policy };
  delete missing.approvedCommit;
  for (const p of [missing, { ...policy, workflowKey: policy.publisherKey }]) {
    write(path.join(root, 'test.json'), p);
    const r = decide([image, 'test', candidate], root);
    assert.equal(r.reason, 'POLICY_INVALID');
    assert.equal(r.approvedImage, null);
  }
});

test('tüketici ret kararını, farklı digest’i ve etiketli teslimi reddeder', () => {
  const good = JSON.parse(run('gate.cjs', [image, 'test', fixture]).stdout);
  for (const change of [{ decision: 'deny' }, { digest: 'sha256:' + 'f'.repeat(64) }, { approvedImage: policy.imageRepository + ':candidate' }]) {
    const next = run('receive.cjs', [fixture], JSON.stringify({ ...good, ...change }));
    assert.equal(next.status, 1);
    assert.equal(next.stdout, '');
  }
});

for (const [file, reason, verified] of [
  ['image.sigstore.json', 'IMAGE_SIGNATURE', [false, false]],
  ['provenance.sigstore.json', 'PROVENANCE_SIGNATURE', [true, false]],
]) {
  test(file + ' metin kodlaması bozulmuşsa ret verir', t => {
    const candidate = workspace(t);
    const filePath = path.join(candidate, file);
    const bundle = json(filePath);
    if (bundle.messageSignature) bundle.messageSignature.signature += '!';
    else bundle.dsseEnvelope.payload += '!';
    write(filePath, bundle);
    denied(run('gate.cjs', [image, 'test', candidate]), reason, verified);
  });
}

test('imzasız doğrulandı beyanı köken kanıtının yerini tutamaz', t => {
  const candidate = workspace(t);
  write(path.join(candidate, 'provenance.sigstore.json'), { verified: true, digest: policy.approvedDigest });
  denied(run('ci.sh', [image, 'test', candidate]), 'PROVENANCE_SIGNATURE', [true, false]);
});

test('istenen doğrulayıcı sürümü sağlanamıyorsa kapı kapanır', t => {
  const scratch = path.dirname(workspace(t));
  const isolated = path.join(scratch, 'isolated-gate');
  fs.mkdirSync(isolated);
  for (const name of ['gate.cjs', 'lib', 'policy']) {
    fs.cpSync(path.join(project, name), path.join(isolated, name), { recursive: true });
  }
  const manifest = json(path.join(project, 'package.json'));
  manifest.dependencies['@sigstore/verify'] = '0.0.0-release-gate-test';
  write(path.join(isolated, 'package.json'), manifest);
  const result = spawnSync(process.execPath, [path.join(isolated, 'gate.cjs'), image, 'test', fixture], { encoding: 'utf8' });
  denied(result, 'VERIFIER_UNAVAILABLE', [false, false]);
});

test('teslim kaydının hem referansı hem özeti başka imaja değiştirilirse alıcı durur', () => {
  const accepted = JSON.parse(run('gate.cjs', [image, 'test', fixture]).stdout);
  const alternate = json(path.join(fixture, 'alternate-index.json')).manifests[0].digest;
  const record = { ...accepted, digest: alternate, approvedImage: policy.imageRepository + '@' + alternate };
  const result = run('receive.cjs', [fixture], JSON.stringify(record));
  assert.equal(result.status, 1);
  assert.equal(JSON.parse(result.stderr).reason, 'HANDOFF_POLICY');
});

test('alıcı farklı imaj deposunu veya artık geçerli olmayan politika kimliğini reddeder', () => {
  const accepted = JSON.parse(run('gate.cjs', [image, 'test', fixture]).stdout);
  for (const change of [
    { policySha256: 'sha256:' + '0'.repeat(64) }, { policyVersion: 'test-v0' },
    { approvedImage: 'registry.example.invalid/workshop/other@' + accepted.digest },
  ]) {
    const result = run('receive.cjs', [fixture], JSON.stringify({ ...accepted, ...change }));
    assert.equal(result.status, 1);
    assert.equal(JSON.parse(result.stderr).reason, 'HANDOFF_POLICY');
  }
});
