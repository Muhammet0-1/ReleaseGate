'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const { stage, verified, policy, archive, bindImage, releases } = require('../phase3/artifact.cjs');
const { Engine, assertContainer, assertResponse, localEndpoint } = require('../phase3/docker.cjs');

const project=path.resolve(__dirname,'..');
const manifest=releases.green.split('@')[1];
const own='b'.repeat(64), other='c'.repeat(64);
const config='sha256:2cd2d487d1fb613e46ad8d0113a2c8f6786f5681c435992d865e75e8a8f1e95a';
const diff='sha256:'+'1'.repeat(64);
const art={edition:'green',manifestDigest:manifest,expectedImageId:config,layerDigest:diff};
const labels={'io.releasegate.project':'phase3','io.releasegate.edition':'green'};
function image(id) {
  return {Id:id,Os:'linux',Architecture:'amd64',Config:{Labels:labels},RootFS:{Layers:[diff]},
    Descriptor:id===manifest?{digest:manifest,mediaType:'application/vnd.oci.image.manifest.v1+json'}:undefined};
}
function scratch(t) {
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'rg3t-'));
  t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  return dir;
}
function binding() {
  const h={a:art,engineId:manifest,binding:'single-manifest-id',id:own,run:'run-a',name:'lab-candidate',role:'candidate',nonce:'nonce-a',volume:'lab-data'};
  const c={Id:own,Image:manifest,ImageManifestDescriptor:{digest:manifest},Name:'/lab-candidate',State:{Running:true},
    Config:{User:'65532:65532',Hostname:'host-a',Labels:{'io.releasegate.project':'phase3','io.releasegate.run':'run-a',
      'io.releasegate.role':'candidate','io.releasegate.instance':'nonce-a'}},
    HostConfig:{NetworkMode:'none',ReadonlyRootfs:true,PortBindings:{},CapDrop:['ALL'],SecurityOpt:['no-new-privileges=true']},
    Mounts:[{Type:'volume',Name:'lab-data',Destination:'/state',RW:true}]};
  return {h,c};
}

test('prepare komutu iki imzalı manifestin gerçek config baytlarından OCI ImageID üretir',t=>{
  const dir=scratch(t);
  const cli=spawnSync(process.execPath,['phase3/demo.cjs','prepare'],{cwd:project,env:{...process.env,TMPDIR:dir},encoding:'utf8'});
  assert.equal(cli.status,0,cli.stdout+cli.stderr);
  const report=JSON.parse(cli.stdout);
  assert.equal(report.outcome,'artifacts_verified');
  assert.equal(report.dockerReached,false);
  assert.equal(report.realContainersStarted,0);
  const logs=fs.readFileSync(path.join(report.runDirectory,'audit.jsonl'),'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(logs.some(e=>e.event==='docker-command'),false);
  assert.equal(logs.filter(e=>e.event==='gate'&&e.decision.imageSignatureVerified&&e.decision.provenanceSignatureVerified).length,2);
  const blob=id=>fs.readFileSync(path.join(project,'phase3/fixture/oci/blobs/sha256',id.slice(7)));
  for(const a of report.artifacts){
    const raw=JSON.parse(blob(a.verifiedManifestDigest));
    const independentlyHashed='sha256:'+createHash('sha256').update(blob(raw.config.digest)).digest('hex');
    assert.equal(a.expectedImageIdFromConfig,independentlyHashed);
    assert.notEqual(a.verifiedManifestDigest,independentlyHashed);
  }
});
test('uzak Docker hedefi CLI ön kontrolünde bağlantı yapılmadan reddedilir',t=>{
  const dir=scratch(t);
  const cli=spawnSync(process.execPath,['phase3/demo.cjs','preflight'],{
    cwd:project,env:{...process.env,TMPDIR:dir,DOCKER_HOST:'tcp://forbidden.example.invalid:2375'},encoding:'utf8'});
  const r=JSON.parse(cli.stdout);
  assert.equal(cli.status,4);
  assert.equal(r.reason,'NONLOCAL_OR_UNKNOWN_CONTEXT');
  assert.equal(r.realContainersStarted,0);
  assert.ok(!fs.readFileSync(path.join(r.runDirectory,'audit.jsonl'),'utf8').includes('docker-command'));
});
test('bilinmeyen veya başka kullanıcıya ait Unix soketi yerel bağlam sayılmaz',()=>{
  for(const value of ['ssh://remote','unix:///tmp/docker.sock','unix:///run/user/999/docker.sock']){
    assert.throws(()=>localEndpoint(value,1000),{code:'NONLOCAL_OR_UNKNOWN_CONTEXT'});
  }
  assert.equal(localEndpoint('unix:///run/user/1000/docker.sock',1000),'unix:///run/user/1000/docker.sock');
});
test('klasik image ID ancak dışa verilen config ile doğrulanabilir',()=>{
  assert.equal(bindImage(art,image(config),config),'config-id');
  const conflicting = { ...image(config), Descriptor:{digest:diff, mediaType:'application/vnd.oci.image.manifest.v1+json'} };
  assert.throws(()=>bindImage(art,conflicting,config),{code:'IMAGE_ID_MISMATCH'});
  assert.throws(()=>bindImage(art,image(config),manifest),{code:'IMAGE_ID_MISMATCH'});
});
test('containerd manifest ID yalnız doğrulanmış tek manifest ve dışa verilen config ile bağlanır',()=>{
  assert.equal(bindImage(art,image(manifest),config),'single-manifest-id');
  const indexed=image(manifest);
  indexed.Descriptor.mediaType='application/vnd.oci.image.index.v1+json';
  assert.throws(()=>bindImage(art,indexed,config),{code:'IMAGE_ID_MISMATCH'});
  assert.throws(()=>bindImage(art,image(manifest),diff),{code:'IMAGE_ID_MISMATCH'});
});
test('uyumlu RepoDigests metni yanlış Docker ID veya eksik platform kanıtını kurtaramaz',()=>{
  const wrong={...image(diff),RepoDigests:[releases.green]};
  assert.throws(()=>bindImage(art,wrong,config),{code:'IMAGE_ID_MISMATCH'});
  const {h,c}=binding();
  delete c.ImageManifestDescriptor;
  assert.throws(()=>assertContainer(h,c),{code:'CONTAINER_MANIFEST_MISSING'});
});
test('görev etiketleri ve imaj aynı olsa da başka gerçek CID kabul edilemez',()=>{
  const {h,c}=binding();
  assert.doesNotThrow(()=>assertContainer(h,c));
  assert.throws(()=>assertContainer(h,{...c,Id:other}),{code:'WRONG_CONTAINER'});
});
test('container inspect Image alanı gözlenir, Config.Image içindeki iddiaya güvenilmez',()=>{
  const {h,c}=binding();
  const substituted={...h,binding:'config-id',engineId:diff};
  const classic={...c,Image:diff,ImageManifestDescriptor:null};
  assert.throws(()=>assertContainer(substituted,classic),{code:'CONTAINER_IMAGE_MISMATCH'});
  c.Config.Image=manifest;
  c.Image=diff;
  assert.throws(()=>assertContainer(h,c),{code:'CONTAINER_IMAGE_MISMATCH'});
});
test('dış port, yabancı volume veya farklı ağ bulunan container ret alır',()=>{
  for(const edit of [c=>{c.HostConfig.PortBindings={'80/tcp':[{}]};},c=>{c.Mounts[0].Name='foreign';},
    c=>{c.HostConfig.NetworkMode='bridge';},c=>{c.HostConfig.Privileged=true;}]){
    const {h,c}=binding();edit(c);
    assert.throws(()=>assertContainer(h,c),{code:'CONTAINER_SCOPE_MISMATCH'});
  }
});
test('HTTP 200 gerçek hedefin instance kimliği ve hostname ile uyuşmalı',()=>{
  const {h,c}=binding();
  for(const body of [{instance:'wrong',hostname:'host-a',edition:'green'},{instance:h.nonce,hostname:'wrong',edition:'green'}]){
    assert.throws(()=>assertResponse(h,c,{status:200,body}),{code:'WRONG_RESPONSE_INSTANCE'});
  }
});
test('kayıp Sigstore kanıtı arşivleme veya Docker işleminden önce reddedilir',t=>{
  const input=stage(scratch(t),'green');
  fs.unlinkSync(path.join(input,'provenance.sigstore.json'));
  assert.throws(()=>verified(input,'green',policy('forward'),()=>{}),{code:'PROVENANCE_SIGNATURE'});
});
test('çevrimdışı arşivde ham config ve manifest birlikte doğrulanır',t=>{
  const root=scratch(t);
  const a=verified(stage(root,'green'),'green',policy('forward'),()=>{});
  const file=archive(root,a,'release-gate.invalid/lab/offline:green');
  const validate=id=>spawnSync('python3',['-B','phase3/check_export.py',file,a.manifestDigest,id,a.manifestDigest],{cwd:project,encoding:'utf8'});
  assert.equal(validate(config).stdout.trim(),config);
  assert.notEqual(validate(diff).status,0);
});

test('bağlantısız imzalı blob, başka manifesti seçen Docker dışa aktarımını doğrulayamaz',t=>{
  const root = scratch(t);
  const release = verified(stage(root,'green'),'green',policy('forward'),()=>{});
  archive(root,release,'release-gate.invalid/lab/offline:green');
  const dir = path.join(root,'load-green');
  const indexFile = path.join(dir,'index.json');
  const index = JSON.parse(fs.readFileSync(indexFile));
  index.manifests[0].digest = diff;
  fs.writeFileSync(indexFile,JSON.stringify(index));
  const file = path.join(root,'detached.tar');
  const tar = spawnSync('tar',['-cf',file,'-C',dir,'index.json','blobs','manifest.json','oci-layout']);
  assert.equal(tar.status,0);
  const checked = spawnSync('python3',['-B','phase3/check_export.py',file,manifest,config,manifest],{cwd:project,encoding:'utf8'});
  assert.notEqual(checked.status,0);
  assert.match(checked.stderr,/index points to a different manifest/);
});

test('klasik Docker arşivinde seçilen tek config ham baytlarından doğrulanır',t=>{
  const root = scratch(t);
  const name = config.slice(7)+'.json';
  const blob = path.join(project,'phase3/fixture/oci/blobs/sha256',config.slice(7));
  fs.copyFileSync(blob,path.join(root,name));
  fs.writeFileSync(path.join(root,'manifest.json'),JSON.stringify([{Config:name,RepoTags:null,Layers:['layer.tar']}]));
  const file = path.join(root,'classic.tar');
  function checkExport() {
    assert.equal(spawnSync('tar',['-cf',file,'-C',root,'manifest.json',name]).status,0);
    return spawnSync('python3',['-B','phase3/check_export.py',file,manifest,config,config],{cwd:project,encoding:'utf8'});
  }
  const valid = checkExport();
  assert.equal(valid.status,0,valid.stderr);
  assert.equal(valid.stdout.trim(),config);
  fs.appendFileSync(path.join(root,name),' ');
  assert.match(checkExport().stderr,/exported config mismatch/);
});

test('temizlikte yabancı container, volume ve çakışan etiket için silme komutu verilmez',t=>{
  const engine = new Engine(scratch(t),()=>{});
  engine.daemonId = 'same-daemon';
  engine.slots.push({id:own,name:'expected',role:'candidate',nonce:'expected-nonce'});
  engine.volumeIntent = true;
  const tag = 'release-gate.invalid/lab/collision:green';
  engine.ownedImages.push({tag,a:art});
  const calls=[];
  engine.call=args=>{ calls.push(args); return args[0]==='info' ? engine.daemonId : ''; };
  engine.inspect=type=>{
    if(type==='container') return {Id:other,Name:'/expected',Config:{Labels:{}}};
    if(type==='volume') return {Name:engine.volume,Driver:'local',Labels:{'io.releasegate.run':'foreign'}};
    return {Id:diff,RepoTags:[tag],Config:{Labels:labels}};
  };
  const problems=engine.cleanup();
  assert.deepEqual(problems.map(p=>p.reason),['CLEANUP_OWNERSHIP','VOLUME_OWNERSHIP','CLEANUP_OWNERSHIP','TAG_REMAINS']);
  assert.ok(calls.every(args=>['info','ls'].includes(args[0]) || args[1]==='ls'));
  assert.ok(!calls.some(args=>args.includes('rm')));
});

test('daemon kimliği değiştiğinde temizlik hiçbir kaynağa başvurmadan durur',t=>{
  const engine = new Engine(scratch(t),()=>{});
  engine.daemonId = 'first';
  const calls = [];
  engine.call = args=>{ calls.push(args); return 'another'; };
  engine.inspect = ()=>assert.fail('Değişen daemon üzerinde kaynak sorgulandı');
  assert.throws(()=>engine.cleanup(),{code:'DAEMON_CHANGED'});
  assert.deepEqual(calls,[['info','--format','{{.ID}}']]);
});
