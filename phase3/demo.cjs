'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { isDeepStrictEqual } = require('node:util');
const { performance } = require('node:perf_hooks');
const { check, Failure, endpoint, request, bounded } = require('../phase2/http.cjs');
const { records } = require('../phase2/rollout.cjs');
const { readPolicyBytes } = require('../lib/policy.cjs');
const { digest } = require('../lib/common.cjs');
const { stage, verified, policy } = require('./artifact.cjs');
const { Engine, publicId, assertContainer } = require('./docker.cjs');

const scenarios = ['promote','unhealthy-503','rollback-revoked','wrong-instance-200','wrong-image-claim'];
const modes = ['preflight','prepare',...scenarios];

function health(engine, expected, target, log) {
  const started = performance.now();
  const reply = engine.http(target,'GET','/ready');
  const elapsedMs = Math.round(performance.now()-started);
  let reason;
  if (target.id !== expected.id || reply.docker.containerId !== expected.id || reply.body.instance !== expected.nonce) reason = 'WRONG_CONTAINER';
  else if (reply.docker.containerImageId !== expected.engineId) reason = 'CONTAINER_IMAGE_MISMATCH';
  else if (elapsedMs > 4500) reason = 'READINESS_DEADLINE';
  else if (reply.status !== 200 || reply.body.ready !== true) reason = reply.status === 503 ? 'HTTP_503' : 'NOT_READY';
  else reason = 'READY';
  const row = {expected:publicId(expected), observed:reply.docker, instance:reply.body.instance, responseHostname:reply.body.hostname,
    http:reply.status, elapsedMs, reason};
  log('direct-readiness',row);
  return row;
}

async function run(mode) {
  check(modes.includes(mode),'USAGE');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(),'rg3-'));
  const fd = fs.openSync(path.join(dir,'audit.jsonl'),'wx',0o600);
  let seq=0, interrupted=false, cleaning=false;
  const work=path.join(dir,'work');
  fs.mkdirSync(work,{mode:0o700});
  function log(event,data={}) {
    if(interrupted && !cleaning) throw new Failure('INTERRUPTED');
    fs.writeFileSync(fd,JSON.stringify({sequence:++seq,time:new Date().toISOString(),scenario:mode,event,...data})+'\n');
    fs.fsyncSync(fd);
  }
  const engine=new Engine(work,log);
  const summary={mode:mode === 'prepare'?'offline-artifact-verification':'docker', scenario:mode, runDirectory:dir, run:engine.run,
    dockerReached:false, realContainersStarted:0, outcome:'stopped', reason:null, candidateReason:null, rollbackReason:null,
    activeAtDecision:null, heldHttp:null, selectedRecords:[], sharedRecords:[], cleanupProblems:[]};
  let active=null, server;
  const onSignal=()=>{interrupted=true;active=null;};
  process.on('SIGINT',onSignal);
  process.on('SIGTERM',onSignal);
  const front=path.join(work,'traffic.sock');
  const shared=(method,route,body)=>request(front,route,{method,body,deadline:8000});
  function select(h, approval, root, purpose) {
    assertContainer(h,engine.inspect('container',h.id));
    check(approval.decision.approvedImage === h.a.decision.approvedImage &&
      approval.expectedImageId === h.a.expectedImageId && digest(readPolicyBytes(root))===approval.decision.policySha256,
      'APPROVAL_CHANGED');
    log('route-selected',{purpose,selected:publicId(h),policyVersion:approval.decision.policyVersion,policySha256:approval.decision.policySha256});
    active=h;
  }
  async function write(rec,h) {
    const reply=await shared('POST','/records',rec);
    log('record-write',{via:'shared',status:reply.status,instance:reply.body?.instance,container:publicId(h),record:reply.body?.record});
    check(reply.status===201 && reply.body?.instance===h.nonce && isDeepStrictEqual(reply.body.record,rec),'DATA_WRITE_FAILED');
  }
  async function readBoth(h, via) {
    const values=[];
    for(const r of records) {
      const route='/records/'+r.id;
      const ans=via==='shared'?await shared('GET',route):engine.http(h,'GET',route);
      log('record-read',{via,container:publicId(h),http:ans.status,instance:ans.body?.instance,record:ans.body?.record});
      check(ans.status===200 && ans.body?.instance===h.nonce && isDeepStrictEqual(ans.body.record,r),'DATA_CHECK_FAILED');
      values.push(ans.body.record);
    }
    return values;
  }
  try {
    log('start',{mode:summary.mode,run:engine.run});
    if(mode!=='prepare') {
      engine.preflight();
      summary.dockerReached=true;
    }
    if(mode==='preflight') {
      summary.outcome='preflight_verified';
    } else {
      const b=stage(work,'blue'), g=stage(work,'green');
      const blue=verified(b,'blue',policy('initial'),log);
      const green=verified(g,'green',policy('forward'),log);
      summary.artifacts=[blue,green].map(a=>({edition:a.edition,reference:a.decision.approvedImage,
        verifiedManifestDigest:a.manifestDigest,expectedImageIdFromConfig:a.expectedImageId,policyVersion:a.decision.policyVersion}));
      if(mode==='prepare') {
        summary.outcome='artifacts_verified';
      } else {
        const rollbackRoot=path.join(work,'operator-rollback');
        fs.mkdirSync(rollbackRoot);
        fs.copyFileSync(path.join(policy('rollback'),'test.json'),path.join(rollbackRoot,'test.json'),fs.constants.COPYFILE_EXCL);
        const oldImage=engine.importImage(blue), upcoming=engine.importImage(green);
        engine.createVolume();
        server=endpoint(async(method,route,body)=>{
          const target=active;
          if(!target) return {status:503,body:{error:'TRAFFIC_HELD'}};
          const response=engine.http(target,method,route,body);
          check(active===target,'ROUTE_CHANGED');
          return response;
        });
        await bounded(new Promise((resolve,reject)=>{server.once('error',reject);server.listen(front,resolve);}),3000,'ROUTER_TIMEOUT');
        const previous=engine.launch('previous',oldImage,'ready');
        check(health(engine,previous,previous,log).reason==='READY','INITIAL_NOT_READY');
        select(previous,blue,policy('initial'),'initial');
        await write(records[0],previous);
        const rejectHealth=['unhealthy-503','rollback-revoked'].includes(mode);
        const candidate=engine.launch('candidate',upcoming,rejectHealth?'503':'ready');
        await write(records[1],previous);
        const old=health(engine,previous,previous,log);
        const common=await shared('GET','/ready');
        const direct=health(engine,candidate,candidate,log);
        let probe=direct;
        if(mode==='wrong-instance-200') {
          const replica=engine.launch('replica-control',upcoming,'ready');
          probe=health(engine,candidate,replica,log);
        }
        if(mode==='wrong-image-claim') {
          // Eski CID ve çalışma kimliği doğru. Yalnız ona yakıştırılan yeşil imaj yanlıştır.
          const actual=engine.inspect('container',previous.id);
          const claim={...previous,a:green,engineId:upcoming.engineId,binding:upcoming.binding};
          let reason='INVALID_BINDING_ACCEPTED';
          try { assertContainer(claim,actual); } catch(error) { reason=error.code; }
          check(reason==='CONTAINER_IMAGE_MISMATCH','INVALID_BINDING_ACCEPTED');
          probe={expected:publicId(candidate),observed:old.observed,instance:previous.nonce,http:old.http,reason};
          log('wrong-image-claim',{containerId:actual.Id,observedDockerImageId:actual.Image,
            claimedDockerImageId:upcoming.engineId,expectedConfig:green.expectedImageId,reason});
        }
        log('readiness-window',{previousHttp:old.http,sharedHttp:common.status,sharedInstance:common.body?.instance,
          previousInstance:previous.nonce,defaultRoute:publicId(active),candidateDirect:direct,decisionProbe:probe});
        check(common.body?.instance===previous.nonce,'SHARED_INSTANCE_MISMATCH');
        summary.candidateReason=probe.reason;
        let chosen;
        if(probe.reason==='READY' && direct.reason==='READY') {
          await readBoth(candidate,'direct-before-promotion');
          select(candidate,green,policy('forward'),'promotion');
          chosen=candidate;
        } else {
          log('candidate-rejected',{candidateReason:probe.reason,defaultRoute:publicId(active)});
          if(mode==='rollback-revoked') {
            const temp=path.join(rollbackRoot,'next.json');
            fs.copyFileSync(path.join(policy('revoked'),'test.json'),temp,fs.constants.COPYFILE_EXCL);
            fs.renameSync(temp,path.join(rollbackRoot,'test.json'));
            log('operator-policy-changed',{policySha256:digest(readPolicyBytes(rollbackRoot))});
          }
          let authorized;
          try { authorized=verified(b,'blue',rollbackRoot,log); }
          catch(error) {
            active=null;
            log('traffic-held',{candidateReason:probe.reason,rollbackReason:error.code||'VERIFICATION_FAILED'});
            summary.outcome='operator_required';
            summary.reason='ROLLBACK_NOT_AUTHORIZED';
            summary.rollbackReason=error.code||'VERIFICATION_FAILED';
          }
          if(authorized) {
            check(health(engine,previous,previous,log).reason==='READY','ROLLBACK_NOT_READY');
            const stillOld=await shared('GET','/ready');
            check(active===previous && stillOld.status===200 && stillOld.body.instance===previous.nonce,'PREVIOUS_ROUTE_CHANGED');
            log('previous-route-retained',{selected:publicId(previous),http:stillOld.status,instance:stillOld.body.instance});
            await readBoth(previous,'direct-before-rollback');
            select(previous,authorized,rollbackRoot,'rollback');
            chosen=previous;
            summary.rollbackReason='APPROVED';
          }
        }
        if(chosen) {
          summary.selectedRecords=await readBoth(chosen,'selected-instance');
          summary.sharedRecords=await readBoth(chosen,'shared');
          summary.activeAtDecision=publicId(chosen);
          summary.outcome=chosen===candidate?'promoted':'rolled_back';
          summary.reason=chosen===candidate?'CANDIDATE_READY':'PREVIOUS_REVERIFIED';
        } else {
          const hold=await shared('GET','/ready');
          check(hold.status===503 && hold.body.error==='TRAFFIC_HELD','HOLD_NOT_CONFIRMED');
          summary.heldHttp=hold.status;
          // Özel eski örnekte veriyi yalnız oku. Ortak rota kapalıdır.
          await readBoth(previous,'isolated-data-check');
        }
      }
    }
  } catch(error) {
    active=null;
    summary.activeAtDecision=null;
    summary.outcome=!summary.dockerReached && mode!=='prepare'?'docker_unavailable':'stopped';
    summary.reason=error.code||'INTERNAL_ERROR';
    summary.detail=String(error.message).slice(0,350);
    try{ log('error',{reason:summary.reason,detail:summary.detail}); }catch{}
  } finally {
    cleaning=true;
    active=null;
    if(server?.listening) {
      try {
        const done=new Promise((res,rej)=>server.close(e=>e?rej(e):res()));
        server.closeAllConnections();
        await bounded(done,2000,'ROUTER_STOP_TIMEOUT');
      } catch(error){summary.cleanupProblems.push({target:'local-router',reason:error.code||'STOP_FAILED'});}
    }
    summary.realContainersStarted=engine.slots.filter(s=>s.containerImageId).length;
    engine.log=(ev,data)=>{try{log(ev,data);}catch{summary.auditFailed=true;}};
    if(engine.slots.length||engine.volumeIntent||engine.ownedImages.length) {
      try { summary.cleanupProblems.push(...engine.cleanup()); }
      catch(error){summary.cleanupProblems.push({target:engine.run,reason:error.code||'CLEANUP_FAILED'});}
    }
    if(!summary.cleanupProblems.length) {
      try { fs.rmSync(work,{recursive:true}); }
      catch(error) { summary.cleanupProblems.push({target:'run-workspace',reason:error.code}); }
    }
    if(interrupted){summary.outcome='stopped';summary.reason='INTERRUPTED';summary.activeAtDecision=null;}
    if(summary.cleanupProblems.length||summary.auditFailed){summary.outcome='stopped';summary.reason='CLEANUP_OR_AUDIT_FAILED';}
    summary.exitCode={preflight_verified:0,artifacts_verified:0,promoted:0,rolled_back:2,operator_required:3,docker_unavailable:4,stopped:1}[summary.outcome];
    try{log('terminal',summary);} catch {summary.outcome='stopped';summary.reason='AUDIT_WRITE_FAILED';summary.exitCode=1;}
    try { fs.closeSync(fd); }
    finally { process.off('SIGINT',onSignal); process.off('SIGTERM',onSignal); }
  }
  return summary;
}

if(require.main===module) {
  const [mode,...rest]=process.argv.slice(2);
  if(!modes.includes(mode)||rest.length){console.error('Kullanım: node phase3/demo.cjs '+modes.join('|'));process.exitCode=1;}
  else run(mode).then(r=>{console.log(JSON.stringify(r));process.exitCode=r.exitCode;}).catch(e=>{
    console.error(JSON.stringify({outcome:'stopped',reason:e.code||'INTERNAL_ERROR'}));process.exitCode=1;
  });
}
module.exports={run,health,scenarios};
