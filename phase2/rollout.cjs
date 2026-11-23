'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { DatabaseSync } = require('node:sqlite');
const { decide } = require('../gate.cjs');
const { digest } = require('../lib/common.cjs');
const { readPolicyBytes } = require('../lib/policy.cjs');
const { readImage } = require('../lib/oci.cjs');
const { Failure, check, request } = require('./http.cjs');
const { identity, matches, probe, startRouter, start, stop, shutdown } = require('./runtime.cjs');

const project = path.resolve(__dirname, '..');
const initialPolicy = path.join(project, 'policy');
const forwardPolicy = path.join(__dirname, 'policies/forward');
const rollbackPolicy = path.join(__dirname, 'policies/rollback');
const revokedPolicy = path.join(__dirname, 'policies/revoked');
const repository = 'registry.example.invalid/workshop/parcel-note';
const blue = repository + '@sha256:7da35d8d71dc40a2c55b7000513f67d861e1a83ac6f5abfe1d8ad124dbc8bd60';
const green = repository + '@sha256:e5f3c66b2640cf9b8f62de683cf4d407943aa733b180da73b5fb5807e5c109a4';
const records = [
  { id: 'before-candidate', value: 'sentetik-koli-17' },
  { id: 'during-staging', value: 'sentetik-koli-29' },
];
const scenarios = {
  promote: {},
  'unhealthy-503': { health: '503' },
  timeout: { health: 'timeout' },
  'wrong-instance-200': { probeShared: true, health: '503' },
  'wrong-replica-200': { probeReplica: true, health: '503' },
  'wrong-digest': { wrongManifest: true },
  'lost-candidate-proof': { loseCandidateProof: true },
  'rollback-revoked': { health: '503', revoke: 'before-verification' },
  'lost-rollback-proof': { health: '503', loseRollbackProof: true },
  'late-revocation': { health: '503', revoke: 'before-switch' },
  'connection-error': { disconnect: true },
  'data-write-error': { readOnlyOnSecond: true },
  'audit-write-error': { closeJournal: true },
};

class Journal {
  constructor(scope) {
    this.scenario = scope.scenario;
    this.run = path.basename(scope.dir);
    this.seq = 0;
    this.fd = fs.openSync(path.join(scope.dir, 'audit.jsonl'), 'wx', 0o600);
  }
  write(event, data = {}) {
    const row = { run: this.run, scenario: this.scenario, sequence: ++this.seq, time: new Date().toISOString(), event, ...data };
    try {
      fs.writeFileSync(this.fd, JSON.stringify(row) + '\n');
      fs.fsyncSync(this.fd);
    } catch {
      throw new Failure('AUDIT_WRITE_FAILED');
    }
  }
  close() {
    if (this.fd !== null) fs.closeSync(this.fd);
    this.fd = null;
  }
}

function prepare(scope) {
  const fixture = path.join(project, 'fixtures/candidate');
  scope.previousFiles = path.join(scope.dir, 'previous-artifact');
  scope.candidateFiles = path.join(scope.dir, 'candidate-artifact');
  for (const directory of [scope.previousFiles, scope.candidateFiles]) {
    fs.cpSync(fixture, directory, { recursive: true, force: false, errorOnExist: true });
  }
  const { alternate } = JSON.parse(fs.readFileSync(path.join(project, 'test/variants.json')));
  fs.writeFileSync(path.join(scope.candidateFiles, 'image.sigstore.json'), JSON.stringify(alternate.image));
  fs.writeFileSync(path.join(scope.candidateFiles, 'provenance.sigstore.json'), JSON.stringify(alternate.provenance));

  scope.rollbackControl = path.join(scope.dir, 'operator-rollback');
  fs.mkdirSync(scope.rollbackControl, { mode: 0o700 });
  fs.copyFileSync(path.join(rollbackPolicy, 'test.json'), path.join(scope.rollbackControl, 'test.json'), fs.constants.COPYFILE_EXCL);
  scope.database = path.join(scope.dir, 'records.sqlite');
  fs.closeSync(fs.openSync(scope.database, 'wx', 0o600));
  const db = new DatabaseSync(scope.database);
  try {
    // Yalnız yeni koşunun boş dosyasında şema oluşturulur. Sonraki aşamalar sadece bu dosyayı açar.
    db.exec('CREATE TABLE store(id TEXT PRIMARY KEY); CREATE TABLE records(id TEXT PRIMARY KEY, value TEXT NOT NULL)');
    scope.store = randomUUID();
    db.prepare('INSERT INTO store(id) VALUES (?)').run(scope.store);
  } finally { db.close(); }
  scope.log.write('store-created', { store: scope.store });
}

function changeRollbackPolicy(scope) {
  const next = path.join(scope.rollbackControl, 'next.json');
  fs.copyFileSync(path.join(revokedPolicy, 'test.json'), next, fs.constants.COPYFILE_EXCL);
  fs.renameSync(next, path.join(scope.rollbackControl, 'test.json'));
  scope.log.write('operator-policy-updated', { policySha256: digest(readPolicyBytes(scope.rollbackControl)) });
}

function admit(scope, purpose, ref, files, policy) {
  const d = decide([ref, 'test', files], policy);
  scope.log.write('gate', { purpose, decision: d });
  return d;
}

function select(scope, instance, decision, policyRoot, purpose) {
  check(decision.decision === 'allow' && instance.image === decision.approvedImage && instance.digest === decision.digest,
    'DECISION_BINDING_FAILED');
  check(digest(readPolicyBytes(policyRoot)) === decision.policySha256, 'POLICY_CHANGED_BEFORE_SWITCH');
  check(!instance.ended, 'PROCESS_EXITED');
  scope.log.write('route-selected', { purpose, selected: identity(instance), policyVersion: decision.policyVersion,
    policySha256: decision.policySha256 });
  scope.router.active = instance;
}

async function writeRecord(scope, previous, record) {
  const result = await request(scope.router.socket, '/records', { method: 'POST', body: record });
  scope.log.write('record-write', { via: 'shared', http: result.status, response: result.body });
  check(result.status === 201 && matches(previous, result.body) && result.body.store === scope.store &&
    isDeepStrictEqual(result.body.record, record), 'DATA_WRITE_FAILED');
}

async function readRecords(scope, instance, socket, via) {
  const read = [];
  for (const expected of records) {
    const { status, body } = await request(socket, '/records/' + expected.id);
    scope.log.write('record-read', { via, http: status, expectedInstance: identity(instance), response: body });
    check(status === 200 && matches(instance, body) && body.store === scope.store &&
      isDeepStrictEqual(body.record, expected), 'DATA_CHECK_FAILED');
    read.push(body.record);
  }
  return read;
}

async function rollout(scope, plan, report) {
  const router = await startRouter(scope);
  const initial = admit(scope, 'initial', blue, scope.previousFiles, initialPolicy);
  check(initial.decision === 'allow', 'INITIAL_' + initial.reason);
  const previous = await start(scope, 'previous', initial, readImage(scope.previousFiles, initial.digest),
    { readOnlyOnSecond: plan.readOnlyOnSecond });
  const baseline = await probe(previous);
  scope.log.write('initial-readiness', { result: baseline });
  check(baseline.reason === 'READY', 'INITIAL_NOT_READY');
  select(scope, previous, initial, initialPolicy, 'initial');
  await writeRecord(scope, previous, records[0]);

  if (plan.loseCandidateProof) fs.unlinkSync(path.join(scope.candidateFiles, 'provenance.sigstore.json'));
  const forward = admit(scope, 'candidate', green, scope.candidateFiles, forwardPolicy);
  let candidate;
  let stagingReason = forward.reason;
  if (forward.decision === 'allow') {
    try {
      const bytes = readImage(scope.candidateFiles, plan.wrongManifest ? initial.digest : forward.digest);
      candidate = await start(scope, 'candidate', forward, bytes, { health: plan.health });
    } catch (error) {
      stagingReason = error.code || 'CANDIDATE_START_FAILED';
      scope.log.write('candidate-start-failed', { reason: stagingReason });
    }
    if (candidate) scope.log.write('candidate-staged', { expected: identity(candidate), defaultRoute: identity(router.active) });
  }
  await writeRecord(scope, previous, records[1]);
  if (plan.disconnect && candidate) await stop(candidate);

  let probeSocket = candidate?.socket;
  let probeSource = 'candidate';
  if (plan.probeShared) {
    probeSocket = router.socket;
    probeSource = 'shared';
  } else if (candidate && plan.probeReplica) {
    const replica = await start(scope, 'other-replica', forward, readImage(scope.candidateFiles, forward.digest));
    scope.log.write('control-replica-started', { instance: identity(replica) });
    probeSocket = replica.socket;
    probeSource = replica.role;
  }
  const [oldProbe, sharedProbe, candidateProbe, directControl] = await Promise.all([
    probe(previous), probe(previous, router.socket, 'shared', false),
    candidate ? probe(candidate, probeSocket, probeSource) : Promise.resolve(null),
    candidate && probeSocket !== candidate.socket ? probe(candidate) : Promise.resolve(null),
  ]);
  scope.log.write('readiness-window', { previous: oldProbe, shared: sharedProbe, candidate: candidateProbe, directControl,
    defaultRoute: identity(router.active) });
  // Kontrol gözlemlerinde ulaşım ve kimlik doğrulanır. Adayın readiness kararını kendi probu verir.
  check([oldProbe, sharedProbe].every(p => ['READY', 'HTTP_503', 'NOT_READY'].includes(p.reason)), 'BASELINE_OBSERVATION_FAILED');
  report.readiness = { previousHttp: oldProbe.http, sharedHttp: sharedProbe.http,
    candidateHttp: candidateProbe?.http ?? null, source: candidateProbe?.source ?? null,
    elapsedMs: candidateProbe?.elapsedMs ?? null, deadlineMs: candidateProbe?.deadlineMs ?? null };
  report.candidateReason = candidateProbe?.reason ?? stagingReason;
  let selected;
  if (report.candidateReason === 'READY') {
    await readRecords(scope, candidate, candidate.socket, 'candidate-before-switch');
    if (plan.closeJournal) scope.log.close();
    select(scope, candidate, forward, forwardPolicy, 'promotion');
    selected = candidate;
  } else {
    // Bekleyen eski rota da kapatılır. Yeniden seçim için güncel kapı kararı gerekir.
    router.active = null;
    scope.log.write('traffic-held', { reason: report.candidateReason });
    if (plan.revoke === 'before-verification') changeRollbackPolicy(scope);
    if (plan.loseRollbackProof) fs.unlinkSync(path.join(scope.previousFiles, 'provenance.sigstore.json'));
    const rollback = admit(scope, 'rollback', previous.image, scope.previousFiles, scope.rollbackControl);
    report.rollbackReason = rollback.reason;
    report.rollbackPolicyVersion = rollback.policyVersion;
    if (rollback.decision !== 'allow') {
      report.outcome = 'operator_required';
      report.reason = 'ROLLBACK_NOT_AUTHORIZED';
      return;
    }
    const healthy = await probe(previous);
    scope.log.write('rollback-readiness', { result: healthy });
    check(healthy.reason === 'READY', 'ROLLBACK_INSTANCE_NOT_READY');
    await readRecords(scope, previous, previous.socket, 'previous-before-reselection');
    if (plan.revoke === 'before-switch') changeRollbackPolicy(scope);
    select(scope, previous, rollback, scope.rollbackControl, 'rollback');
    selected = previous;
  }

  report.selectedRecords = await readRecords(scope, selected, selected.socket, 'selected-instance');
  report.sharedRecords = await readRecords(scope, selected, router.socket, 'shared-after-selection');
  report.activeAtDecision = identity(selected);
  report.outcome = selected === candidate ? 'promoted' : 'rolled_back';
  report.reason = selected === candidate ? 'CANDIDATE_READY' : 'PREVIOUS_REVERIFIED';
}

async function runScenario(name, parent = os.tmpdir()) {
  check(Object.hasOwn(scenarios, name), 'UNKNOWN_SCENARIO');
  const scope = { scenario: name, children: [] };
  const report = { mode: 'local-process-unix-http', scenario: name, runDirectory: null, outcome: 'stopped',
    reason: null, candidateReason: null, rollbackReason: null, rollbackPolicyVersion: null,
    activeAtDecision: null, selectedRecords: [], sharedRecords: [], heldHttp: null, auditComplete: false };
  function fail(error) {
    if (scope.router) scope.router.active = null;
    report.activeAtDecision = null;
    const code = error.code || 'INTERNAL_ERROR';
    if (report.rollbackReason && code === 'POLICY_CHANGED_BEFORE_SWITCH') {
      report.outcome = 'operator_required';
      report.reason = 'ROLLBACK_POLICY_CHANGED';
      report.rollbackReason = code;
    } else {
      report.outcome = 'stopped';
      report.reason = code;
    }
  }
  try {
    scope.dir = fs.mkdtempSync(path.join(parent, 'rg2-'));
    report.runDirectory = scope.dir;
    scope.log = new Journal(scope);
    scope.log.write('start', { mode: report.mode, previousImage: blue, requestedImage: green });
    prepare(scope);
    await rollout(scope, scenarios[name], report);
  } catch (error) {
    fail(error);
  }
  if (scope.router?.server.listening && !scope.router.active) {
    try {
      const held = await request(scope.router.socket, '/ready');
      check(held.status === 503 && held.body?.error === 'TRAFFIC_HELD', 'HOLD_NOT_CONFIRMED');
      report.heldHttp = held.status;
    } catch (error) { fail(error); }
  }
  try { await shutdown(scope); } catch (error) { fail(error); }
  report.childrenStopped = scope.children.every(i => i.ended);
  report.processes = scope.children.map(i => ({ ...identity(i), ended: i.ended, exitCode: i.child.exitCode, signal: i.child.signalCode }));
  try {
    if (scope.log) {
      scope.log.write('terminal', { outcome: report.outcome, reason: report.reason, candidateReason: report.candidateReason,
        rollbackReason: report.rollbackReason, activeAtDecision: report.activeAtDecision, heldHttp: report.heldHttp,
        childrenStopped: report.childrenStopped, processes: report.processes });
      scope.log.close();
      report.auditComplete = true;
    }
  } catch (error) {
    fail(error);
    try { scope.log.close(); } catch { /* Önceki hata zaten başarısız sonuç üretti. */ }
  }
  report.operatorRequired = ['operator_required', 'stopped'].includes(report.outcome);
  report.exitCode = { promoted: 0, stopped: 1, rolled_back: 2, operator_required: 3 }[report.outcome];
  return report;
}

module.exports = { runScenario, scenarios: Object.keys(scenarios), blue, green, records };
