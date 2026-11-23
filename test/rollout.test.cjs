'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { spawnSync } = require('node:child_process');
const { DatabaseSync } = require('node:sqlite');
const { test } = require('node:test');
const { runScenario, blue, green, records } = require('../phase2/rollout.cjs');
const { request } = require('../phase2/http.cjs');

const project = path.resolve(__dirname, '..');
const dig = ref => ref.split('@')[1];

function sandbox(t) {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'rg2test-'));
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  return parent;
}

function stored(database) {
  const db = new DatabaseSync(database, { readOnly: true });
  try {
    return {
      store: db.prepare('SELECT id FROM store').get().id,
      records: db.prepare('SELECT id, value FROM records ORDER BY rowid').all().map(row => ({ ...row })),
    };
  } finally { db.close(); }
}

function scenario(t, name, exitCode) {
  const parent = sandbox(t);
  const cli = spawnSync(process.execPath, ['phase2/demo.cjs', name], {
    cwd: project, env: { ...process.env, TMPDIR: parent }, encoding: 'utf8', timeout: 13000,
  });
  assert.ifError(cli.error);
  assert.equal(cli.status, exitCode, cli.stdout + cli.stderr);
  const r = JSON.parse(cli.stdout);
  assert.equal(r.exitCode, exitCode);
  assert.equal(r.mode, 'local-process-unix-http');
  assert.equal(r.childrenStopped, true);
  assert.equal(path.dirname(r.runDirectory), parent);
  assert.equal(fs.statSync(r.runDirectory).mode & 0o777, 0o700);
  assert.equal(r.processes.every(p => p.ended), true);
  for (const name of ['previous.sock', 'candidate.sock', 'shared.sock']) {
    assert.equal(fs.existsSync(path.join(r.runDirectory, name)), false);
  }
  const log = fs.readFileSync(path.join(r.runDirectory, 'audit.jsonl'), 'utf8').trim().split('\n').map(line => JSON.parse(line));
  assert.deepEqual(log.map(row => row.sequence), log.map((_, i) => i + 1));
  assert.equal(log.every(e => e.scenario === name), true);
  assert.equal(log[0].event, 'start');
  if (name !== 'audit-write-error') {
    assert.equal(r.auditComplete, true);
    assert.equal(log.at(-1).event, 'terminal');
    assert.equal(log.at(-1).outcome, r.outcome);
    assert.equal(log.at(-1).childrenStopped, true);
  }
  return { r, log, data: stored(path.join(r.runDirectory, 'records.sqlite')) };
}

function gate(log, purpose) {
  return log.find(row => row.event === 'gate' && row.purpose === purpose).decision;
}
function routes(log) {
  return log.filter(row => row.event === 'route-selected').map(row => row.purpose);
}
function windowOf(log) {
  const window = log.find(row => row.event === 'readiness-window');
  assert.equal(window.defaultRoute.image, blue);
  for (const item of [window.previous, window.shared]) {
    assert.equal(item.http, 200);
    assert.equal(item.reason, 'READY');
    assert.equal(item.observed.pid, window.defaultRoute.pid);
    assert.equal(item.observed.digest, dig(blue));
  }
  return window;
}
function checkData(trace, ref) {
  const { r, log, data } = trace;
  assert.deepEqual(data.records, records);
  assert.deepEqual(r.selectedRecords, records);
  assert.deepEqual(r.sharedRecords, records);
  assert.equal(r.activeAtDecision.image, ref);
  assert.equal(r.activeAtDecision.digest, dig(ref));
  const writes = log.filter(e => e.event === 'record-write');
  assert.deepEqual(writes.map(w => w.response.record), records);
  assert.ok(writes.every(w => w.http === 201 && w.response.store === data.store && w.response.digest === dig(blue)));
  const selected = log.filter(e => e.event === 'record-read' && e.via === 'selected-instance');
  const shared = log.filter(e => e.event === 'record-read' && e.via === 'shared-after-selection');
  for (const checks of [selected, shared]) {
    assert.deepEqual(checks.map(e => e.response.record), records);
    assert.ok(checks.every(e => e.http === 200 && e.response.pid === r.activeAtDecision.pid &&
      e.response.instanceId === r.activeAtDecision.instanceId && e.response.digest === dig(ref) && e.response.store === data.store));
  }
}
function rollback(trace, failure) {
  const { r, log } = trace;
  assert.equal(r.outcome, 'rolled_back');
  assert.equal(r.candidateReason, failure);
  assert.equal(r.rollbackReason, 'APPROVED');
  assert.equal(r.operatorRequired, false);
  assert.deepEqual(routes(log), ['initial', 'rollback']);
  assert.equal(gate(log, 'rollback').policyVersion, 'phase2-rollback-v1');
  assert.notEqual(gate(log, 'rollback').policySha256, gate(log, 'initial').policySha256);
  assert.equal(gate(log, 'rollback').approvedImage, blue);
  assert.ok(gate(log, 'rollback').imageSignatureVerified && gate(log, 'rollback').provenanceSignatureVerified);
  const held = log.find(e => e.event === 'traffic-held');
  assert.ok(held.sequence < log.find(e => e.event === 'gate' && e.purpose === 'rollback').sequence);
  const previous = log.find(e => e.event === 'route-selected' && e.purpose === 'initial').selected;
  assert.deepEqual(r.activeAtDecision, previous);
  checkData(trace, blue);
}
function hold(trace, reason) {
  const { r, log, data } = trace;
  assert.deepEqual(routes(log), ['initial']);
  assert.equal(r.outcome, 'operator_required');
  assert.equal(r.operatorRequired, true);
  assert.equal(r.rollbackReason, reason);
  assert.equal(r.activeAtDecision, null);
  assert.equal(r.heldHttp, 503);
  assert.deepEqual(data.records, records);
}

test('iki gerçek Sigstore imzasıyla kabul edilen aday yalnız kendi readiness yanıtı ve veri kontrolünden sonra terfi eder', t => {
  const trace = scenario(t, 'promote', 0);
  const { r, log } = trace;
  const w = windowOf(log);
  assert.equal(w.candidate.reason, 'READY');
  assert.equal(w.candidate.source, 'candidate');
  assert.equal(w.candidate.http, 200);
  assert.notEqual(w.candidate.observed.pid, w.previous.observed.pid);
  assert.notEqual(w.candidate.observed.instanceId, w.previous.observed.instanceId);
  assert.equal(w.candidate.observed.digest, dig(green));
  const candidateGate = gate(log, 'candidate');
  assert.equal(candidateGate.approvedImage, green);
  assert.ok(candidateGate.imageSignatureVerified && candidateGate.provenanceSignatureVerified);
  assert.equal(candidateGate.policyVersion, 'phase2-forward-v1');
  assert.deepEqual(routes(log), ['initial', 'promotion']);
  const switchSeq = log.find(e => e.event === 'route-selected' && e.purpose === 'promotion').sequence;
  assert.ok(log.find(e => e.via === 'candidate-before-switch').sequence < switchSeq && w.sequence < switchSeq);
  assert.equal(r.outcome, 'promoted');
  assert.equal(r.activeAtDecision.pid, w.candidate.observed.pid);
  checkData(trace, green);
});

test('eski örnek ve ortak adres 200 iken adayın 503 yanıtı terfiyi durdurur', t => {
  const trace = scenario(t, 'unhealthy-503', 2);
  assert.equal(windowOf(trace.log).candidate.http, 503);
  const staged = trace.log.find(e => e.event === 'candidate-staged').sequence;
  const writes = trace.log.filter(e => e.event === 'record-write');
  assert.ok(writes[0].sequence < staged && staged < writes[1].sequence);
  rollback(trace, 'HTTP_503');
});

test('eski ve ortak 200 iken yanıt vermeyen aday toplam süre dolunca reddedilir', t => {
  const trace = scenario(t, 'timeout', 2);
  const { candidate } = windowOf(trace.log);
  assert.equal(candidate.http, null);
  assert.equal(candidate.transportError, 'DEADLINE_EXCEEDED');
  assert.ok(candidate.elapsedMs >= candidate.deadlineMs - 10 && candidate.elapsedMs < candidate.deadlineMs + 1800);
  rollback(trace, 'READINESS_TIMEOUT');
});

test('yanlış örneğin gerçek HTTP 200 yanıtı ve sağlıksız adayın doğrudan 503 yanıtı ayırt edilir', t => {
  const trace = scenario(t, 'wrong-instance-200', 2);
  const w = windowOf(trace.log);
  assert.equal(w.candidate.http, 200);
  assert.equal(w.candidate.source, 'shared');
  assert.equal(w.candidate.observed.pid, w.previous.observed.pid);
  assert.notEqual(w.candidate.observed.pid, w.candidate.expected.pid);
  assert.equal(w.directControl.http, 503);
  assert.equal(w.directControl.observed.pid, w.candidate.expected.pid);
  rollback(trace, 'WRONG_INSTANCE');
});

test('aynı onaylı digest ile açılan başka replikanın 200 yanıtı da adayı terfi ettiremez', t => {
  const trace = scenario(t, 'wrong-replica-200', 2);
  const w = windowOf(trace.log);
  assert.equal(w.candidate.source, 'other-replica');
  assert.equal(w.candidate.http, 200);
  assert.equal(w.candidate.observed.digest, w.candidate.expected.digest);
  assert.notEqual(w.candidate.observed.pid, w.candidate.expected.pid);
  assert.notEqual(w.candidate.observed.instanceId, w.candidate.expected.instanceId);
  assert.equal(w.directControl.http, 503);
  rollback(trace, 'WRONG_INSTANCE');
});

test('doğru aday PID’sinin 200 yanıtında başka manifestin digest’i varsa terfi edilmez', t => {
  const trace = scenario(t, 'wrong-digest', 2);
  const { candidate } = windowOf(trace.log);
  assert.equal(candidate.http, 200);
  assert.equal(candidate.observed.pid, candidate.expected.pid);
  assert.equal(candidate.observed.instanceId, candidate.expected.instanceId);
  assert.equal(candidate.observed.digest, dig(blue));
  assert.equal(candidate.expected.digest, dig(green));
  rollback(trace, 'WRONG_DIGEST');
});

test('aday köken kanıtı kayıpsa aday süreç hiç başlatılmaz', t => {
  const trace = scenario(t, 'lost-candidate-proof', 2);
  assert.equal(gate(trace.log, 'candidate').provenanceSignatureVerified, false);
  assert.equal(gate(trace.log, 'candidate').reason, 'PROVENANCE_SIGNATURE');
  assert.equal(trace.r.processes.length, 1);
  assert.equal(windowOf(trace.log).candidate, null);
  rollback(trace, 'PROVENANCE_SIGNATURE');
});

test('güncellenen geri dönüş politikasının reddettiği önceki sürüm otomatik seçilmez', t => {
  const trace = scenario(t, 'rollback-revoked', 3);
  const g = gate(trace.log, 'rollback');
  assert.equal(g.policyVersion, 'phase2-rollback-v2');
  assert.ok(g.imageSignatureVerified && g.provenanceSignatureVerified);
  assert.equal(trace.r.candidateReason, 'HTTP_503');
  assert.equal(trace.r.reason, 'ROLLBACK_NOT_AUTHORIZED');
  hold(trace, 'DIGEST_NOT_APPROVED');
});

test('önceki imajın kanıtı sonradan kaybolursa ilk kabul sonucu tekrar kullanılamaz', t => {
  const trace = scenario(t, 'lost-rollback-proof', 3);
  assert.equal(gate(trace.log, 'initial').decision, 'allow');
  assert.equal(gate(trace.log, 'rollback').provenanceSignatureVerified, false);
  hold(trace, 'PROVENANCE_SIGNATURE');
});

test('geri dönüşe izin verildikten sonra politika değişirse rota kapalı kalır', t => {
  const trace = scenario(t, 'late-revocation', 3);
  assert.equal(gate(trace.log, 'rollback').decision, 'allow');
  assert.equal(trace.r.reason, 'ROLLBACK_POLICY_CHANGED');
  hold(trace, 'POLICY_CHANGED_BEFORE_SWITCH');
});

test('kendi aday sürecinin kapanması sonrası soket bağlantı hatası başarı sayılamaz', t => {
  const trace = scenario(t, 'connection-error', 2);
  const candidate = windowOf(trace.log).candidate;
  assert.equal(candidate.http, null);
  assert.ok(['ENOENT', 'ECONNREFUSED'].includes(candidate.transportError));
  rollback(trace, 'CONNECTION_FAILED');
});

test('SQLite yazmayı reddederse eski kayıt korunur ve yönlendirme kapanır', t => {
  const trace = scenario(t, 'data-write-error', 1);
  const { r, log, data } = trace;
  assert.equal(r.outcome, 'stopped');
  assert.equal(r.reason, 'DATA_WRITE_FAILED');
  assert.equal(r.heldHttp, 503);
  assert.equal(r.activeAtDecision, null);
  assert.equal(log.filter(e => e.event === 'record-write').at(-1).response.error, 'DB_WRITE_FAILED');
  assert.deepEqual(routes(log), ['initial']);
  assert.deepEqual(data.records, [records[0]]);
});

test('karar günlüğü yazılamıyorsa sağlıklı aday dahi seçilmez ve CLI sıfır dönmez', t => {
  const { r, log, data } = scenario(t, 'audit-write-error', 1);
  assert.equal(r.reason, 'AUDIT_WRITE_FAILED');
  assert.equal(r.auditComplete, false);
  assert.equal(r.operatorRequired, true);
  assert.equal(r.activeAtDecision, null);
  assert.equal(r.heldHttp, 503);
  assert.deepEqual(routes(log), ['initial']);
  assert.deepEqual(data.records, records);
});

test('yazma izni verilmeyen gerçek CLI süreci güvenli durur', t => {
  const parent = sandbox(t);
  const cli = spawnSync(process.execPath, ['--permission', '--allow-fs-read=' + project, 'phase2/demo.cjs', 'promote'],
    { cwd: project, env: { ...process.env, TMPDIR: parent }, encoding: 'utf8' });
  assert.equal(cli.status, 1);
  const report = JSON.parse(cli.stdout);
  assert.equal(report.outcome, 'stopped');
  assert.equal(report.reason, 'ERR_ACCESS_DENIED');
  assert.equal(report.runDirectory, null);
  assert.equal(report.auditComplete, false);
  assert.deepEqual(report.processes, []);
  assert.deepEqual(fs.readdirSync(parent), []);
});

test('aynı anda çalışan iki demo birbirinin verisine, soketine veya sürecine karışmaz', async t => {
  const parent = sandbox(t);
  const [a, b] = await Promise.all([runScenario('promote', parent), runScenario('unhealthy-503', parent)]);
  assert.equal(a.outcome, 'promoted');
  assert.equal(b.outcome, 'rolled_back');
  assert.notEqual(a.runDirectory, b.runDirectory);
  const sa = stored(path.join(a.runDirectory, 'records.sqlite'));
  const sb = stored(path.join(b.runDirectory, 'records.sqlite'));
  assert.notEqual(sa.store, sb.store);
  assert.deepEqual(sa.records, records);
  assert.deepEqual(sb.records, records);
  assert.equal(new Set([...a.processes, ...b.processes].map(p => p.instanceId)).size, 4);
});

test('başlıkları gönderen fakat gövdeyi tamamlamayan örnek de mutlak süreye tabidir', async t => {
  const socket = path.join(sandbox(t), 'partial.sock');
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.write('{"partial":');
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(socket, resolve); });
  try {
    await assert.rejects(request(socket, '/ready', { deadline: 90 }), e => e.code === 'DEADLINE_EXCEEDED');
  } finally {
    const closed = new Promise(resolve => server.close(resolve));
    server.closeAllConnections();
    await closed;
  }
});
