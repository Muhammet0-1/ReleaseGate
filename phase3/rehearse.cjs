'use strict';

// Bu dosya açıkça çalıştırıldığında gerçek, görev etiketli Docker kaynakları kullanır.
const { test, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const { records } = require('../phase2/rollout.cjs');
const { localEndpoint } = require('./docker.cjs');
const project=path.resolve(__dirname,'..');
const results=[];
const cases=[
  ['promote',0,'promoted','READY'],
  ['unhealthy-503',2,'rolled_back','HTTP_503'],
  ['rollback-revoked',3,'operator_required','HTTP_503'],
  ['wrong-instance-200',2,'rolled_back','WRONG_CONTAINER'],
  ['wrong-image-claim',2,'rolled_back','CONTAINER_IMAGE_MISMATCH'],
];

for(const [scenario,exit,outcome,reason] of cases) test('gerçek Docker / '+scenario,t=>{
  const scratch=fs.mkdtempSync(path.join(os.tmpdir(),'rg3-live-'));
  const cli=spawnSync(process.execPath,['phase3/demo.cjs',scenario],{cwd:project,
    env:{...process.env,TMPDIR:scratch},encoding:'utf8',timeout:180000});
  assert.ifError(cli.error);
  const report=JSON.parse(cli.stdout);
  assert.equal(cli.status,exit,JSON.stringify(report));
  assert.equal(report.outcome,outcome);
  assert.ok(report.dockerReached);
  assert.equal(report.realContainersStarted,scenario==='wrong-instance-200'?3:2);
  assert.equal(report.candidateReason,reason);
  assert.deepEqual(report.cleanupProblems,[]);
  const bytes=fs.readFileSync(path.join(report.runDirectory,'audit.jsonl'),'utf8');
  const events=bytes.trim().split('\n').map(line=>JSON.parse(line));
  const one=event=>events.find(e=>e.event===event);
  const many=event=>events.filter(e=>e.event===event);
  assert.deepEqual(events.map(e=>e.sequence),events.map((_,i)=>i+1));
  assert.equal(events.at(-1).event,'terminal');
  for(const e of many('gate').filter(e=>e.decision.decision==='allow')){
    assert.ok(e.decision.imageSignatureVerified && e.decision.provenanceSignatureVerified);
  }
  const images=many('image-binding');
  assert.equal(images.length,2);
  for(const i of images){
    assert.equal(i.expectedImageIdFromConfig,i.exportedConfigImageId);
    assert.notEqual(i.expectedImageIdFromConfig,i.verifiedManifestDigest);
    assert.ok([i.verifiedManifestDigest,i.expectedImageIdFromConfig].includes(i.dockerImageId));
  }
  const previous=many('container-started').find(h=>h.role==='previous');
  const candidate=many('container-started').find(h=>h.role==='candidate');
  assert.notEqual(previous.containerId,candidate.containerId);
  // Beklentiyi denetleyicinin özetinden bağımsız olarak operatör politikasından ve ham OCI baytlarından al.
  for(const h of many('container-started')){
    const blue = h.role === 'previous';
    const policyPath = path.join(__dirname,'policies',blue ? 'initial' : 'forward','test.json');
    const approval = JSON.parse(fs.readFileSync(policyPath));
    const blob = id => fs.readFileSync(path.join(__dirname,'fixture/oci/blobs/sha256',id.slice(7)));
    const hash = bytes => 'sha256:'+createHash('sha256').update(bytes).digest('hex');
    const manifestBytes = blob(approval.approvedDigest);
    assert.equal(hash(manifestBytes),approval.approvedDigest);
    const expectedConfig = JSON.parse(manifestBytes).config.digest;
    assert.equal(hash(blob(expectedConfig)),expectedConfig);
    const loaded = images.find(image => image.edition === (blue ? 'blue' : 'green'));
    assert.equal(h.approvedImage,approval.imageRepository+'@'+approval.approvedDigest);
    assert.equal(h.verifiedManifestDigest,approval.approvedDigest);
    assert.equal(h.expectedImageIdFromConfig,expectedConfig);
    assert.equal(loaded.verifiedManifestDigest,approval.approvedDigest);
    assert.equal(loaded.exportedConfigImageId,expectedConfig);
    assert.equal(h.dockerImageId,loaded.dockerImageId);
    assert.equal(h.containerImageId,loaded.dockerImageId);
    if (loaded.binding === 'single-manifest-id') assert.equal(h.containerManifest,approval.approvedDigest);
    assert.match(h.containerId,/^[0-9a-f]{64}$/);
  }
  const w=one('readiness-window');
  assert.equal(w.previousHttp,200);assert.equal(w.sharedHttp,200);
  assert.equal(w.sharedInstance,previous.instance);
  assert.equal(w.defaultRoute.containerId,previous.containerId);
  assert.equal(w.candidateDirect.observed.containerId,candidate.containerId);
  assert.equal(w.candidateDirect.instance,candidate.instance);
  assert.equal(w.candidateDirect.responseHostname,candidate.hostname);
  assert.equal(w.candidateDirect.http,['unhealthy-503','rollback-revoked'].includes(scenario)?503:200);
  const routes=many('route-selected');
  assert.equal(routes[0].selected.containerId,previous.containerId);
  const writes=many('record-write');
  assert.deepEqual(writes.map(e=>e.record),records);
  assert.ok(writes.every(e=>e.status===201 && e.instance===previous.instance));
  assert.ok(writes[0].sequence<candidate.sequence && candidate.sequence<writes[1].sequence);
  if(outcome==='operator_required'){
    assert.equal(report.reason,'ROLLBACK_NOT_AUTHORIZED');
    assert.equal(report.rollbackReason,'DIGEST_NOT_APPROVED');
    assert.equal(many('gate').at(-1).decision.policyVersion,'docker-rollback-v2');
    assert.equal(report.activeAtDecision,null);assert.equal(report.heldHttp,503);assert.equal(routes.length,1);
    const store=many('record-read').filter(e=>e.via==='isolated-data-check');
    assert.deepEqual(store.map(e=>e.record),records);
    assert.ok(store.every(e=>e.instance===previous.instance && e.http===200));
  }else{
    const picked=outcome==='promoted'?candidate:previous;
    assert.equal(report.activeAtDecision.containerId,picked.containerId);
    assert.equal(report.activeAtDecision.containerImageId,picked.dockerImageId);
    assert.equal(routes.length,2);
    assert.equal(routes[1].selected.containerId,picked.containerId);
    for(const via of ['selected-instance','shared']){
      const reads=many('record-read').filter(e=>e.via===via);
      assert.deepEqual(reads.map(e=>e.record),records);
      assert.ok(reads.every(e=>e.http===200 && e.instance===picked.instance && e.container.containerId===picked.containerId));
    }
    if(outcome==='rolled_back'){
      assert.equal(report.rollbackReason,'APPROVED');
      assert.equal(many('gate').at(-1).decision.policyVersion,'docker-rollback-v1');
      assert.equal(one('previous-route-retained').http,200);
      assert.equal(one('previous-route-retained').selected.containerId,previous.containerId);
      assert.equal(many('traffic-held').length,0);
    }
  }
  if(scenario==='wrong-instance-200'){
    assert.equal(w.decisionProbe.http,200);
    assert.notEqual(w.decisionProbe.observed.containerId,candidate.containerId);
    assert.equal(w.decisionProbe.observed.containerImageId,candidate.containerImageId);
    assert.equal(w.candidateDirect.reason,'READY');
  }
  if(scenario==='wrong-image-claim'){
    const claim=one('wrong-image-claim');
    assert.equal(claim.containerId,previous.containerId);
    assert.notEqual(claim.observedDockerImageId,claim.claimedDockerImageId);
  }
  const clean=one('cleanup-verified');
  assert.ok(clean);
  const socket=localEndpoint(one('preflight').socket);
  function remaining(args){
    const check=spawnSync('docker',['--host',socket,...args],{encoding:'utf8',timeout:10000});
    assert.equal(check.status,0,check.stderr);
    return check.stdout.trim();
  }
  const filter='label=io.releasegate.run='+report.run;
  assert.equal(remaining(['container','ls','-aq','--filter',filter]),'');
  assert.equal(remaining(['volume','ls','-q','--filter',filter]),'');
  for(const tag of clean.ownedTags) assert.equal(remaining(['image','ls','-q','--filter','reference='+tag]),'');
  results.push(bytes+JSON.stringify({event:'observer-check',scenario,exitCode:cli.status,outcome,run:report.run,
    candidateReason:reason,rollbackReason:report.rollbackReason,activeAtDecision:report.activeAtDecision,heldHttp:report.heldHttp,
    records:outcome==='operator_required'?many('record-read').filter(e=>e.via==='isolated-data-check').map(e=>e.record):report.selectedRecords,
    remainingContainers:[],remainingVolumes:[],remainingTaskTags:[]})+'\n');
  t.after(()=>fs.rmSync(scratch,{recursive:true,force:true}));
});

after(()=>{
  if(process.env.RG3_EVIDENCE && results.length===cases.length){
    fs.writeFileSync(process.env.RG3_EVIDENCE,results.join(''),{flag:'wx',mode:0o600});
  }
});
