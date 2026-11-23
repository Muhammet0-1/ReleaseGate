'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { randomUUID } = require('node:crypto');
const { check, Failure } = require('../phase2/http.cjs');
const { archive, bindImage } = require('./artifact.cjs');

const owner = 'io.releasegate.project', runLabel = 'io.releasegate.run', roleLabel = 'io.releasegate.role', nonceLabel = 'io.releasegate.instance';
const cid = /^[0-9a-f]{64}$/;
function localEndpoint(uri, uid = process.getuid()) {
  const ok = ['unix:///var/run/docker.sock', 'unix:///run/docker.sock', 'unix:///run/user/' + uid + '/docker.sock'];
  check(ok.includes(uri), 'NONLOCAL_OR_UNKNOWN_CONTEXT');
  return uri;
}
function assertContainer(h, c, { running = true } = {}) {
  check(cid.test(h.id) && c.Id === h.id && c.Name === '/' + h.name && c.Config?.Labels?.[owner] === 'phase3' &&
    c.Config.Labels[runLabel] === h.run && c.Config.Labels[roleLabel] === h.role && c.Config.Labels[nonceLabel] === h.nonce,
    'WRONG_CONTAINER');
  const boundId = h.binding === 'config-id' ? h.a.expectedImageId : h.a.manifestDigest;
  check(['config-id', 'single-manifest-id'].includes(h.binding) && h.engineId === boundId && c.Image === boundId &&
    (!c.ImageManifestDescriptor || c.ImageManifestDescriptor.digest === h.a.manifestDigest), 'CONTAINER_IMAGE_MISMATCH');
  if (h.binding === 'single-manifest-id') check(c.ImageManifestDescriptor?.digest === h.a.manifestDigest, 'CONTAINER_MANIFEST_MISSING');
  const mounts = c.Mounts || [];
  const volumes = mounts.filter(m => m.Type === 'volume');
  check(c.HostConfig?.NetworkMode === 'none' && !c.HostConfig.Privileged && c.HostConfig.ReadonlyRootfs &&
    !Object.keys(c.HostConfig.PortBindings || {}).length && !c.HostConfig.PublishAllPorts &&
    c.HostConfig.CapDrop?.includes('ALL') && c.HostConfig.SecurityOpt?.some(s=>s==='no-new-privileges' || s==='no-new-privileges=true') &&
    !c.HostConfig.Binds?.length && c.Config.User === '65532:65532' &&
    mounts.every(m => m.Type === 'volume' || (m.Type === 'tmpfs' && m.Destination === '/tmp')) &&
    volumes.length === 1 && volumes[0].Name === h.volume && volumes[0].Destination === '/state' && volumes[0].RW === true, 'CONTAINER_SCOPE_MISMATCH');
  if (running) check(c.State?.Running === true, 'CONTAINER_NOT_RUNNING');
}
function assertResponse(h, c, reply) {
  check(reply?.body?.instance === h.nonce && reply.body.hostname === c.Config.Hostname &&
    reply.body.edition === h.a.edition, 'WRONG_RESPONSE_INSTANCE');
}

class Engine {
  constructor(dir, log) {
    this.dir = dir;
    this.log = log;
    this.run = randomUUID();
    this.prefix = 'rg3-' + this.run;
    this.volume = this.prefix + '-data';
    this.ownedImages = [];
    this.slots = [];
    this.volumeIntent = false;
  }
  call(args, { optional = false, timeout = 12000, local = false } = {}) {
    const command = local ? args : ['--host', this.socket, ...args];
    const r = spawnSync('docker', command, { encoding: 'utf8', timeout, maxBuffer: 4 * 1024 * 1024 });
    const msg = String(r.stderr || '').trim();
    const absent = optional && r.status === 1 && /no such (image|object|container|volume)|not found:/.test(msg.toLowerCase());
    this.log('docker-command', { argv: ['docker', ...command], exit: r.status, absent, error: r.status && !absent ? msg.slice(0,350) : undefined });
    if (r.status === 0) return r.stdout.trim();
    if (absent) return null;
    const error = new Failure(/permission denied|cannot connect/i.test(msg) ? 'DOCKER_UNAVAILABLE' : 'DOCKER_COMMAND_FAILED');
    error.message = msg.slice(0,300) || r.error?.message || error.code;
    throw error;
  }
  preflight() {
    if (process.env.DOCKER_HOST) localEndpoint(process.env.DOCKER_HOST);
    const ctx = this.call(['context','show'], { local: true });
    check(ctx.length && !ctx.startsWith('-'), 'INVALID_CONTEXT');
    const info = JSON.parse(this.call(['context','inspect',ctx], { local: true }))[0];
    const endpoint = localEndpoint(info.Endpoints?.docker?.Host);
    if (process.env.DOCKER_HOST) check(localEndpoint(process.env.DOCKER_HOST) === endpoint, 'CONTEXT_OVERRIDE');
    check(!process.env.DOCKER_TLS_VERIFY && !process.env.DOCKER_CERT_PATH, 'CONTEXT_OVERRIDE');
    const socket = fs.realpathSync(endpoint.slice(7));
    localEndpoint('unix://' + socket);
    const stat = fs.statSync(socket);
    check(stat.isSocket() && !(stat.mode & 2) && [0, process.getuid()].includes(stat.uid), 'UNTRUSTED_SOCKET');
    this.socket = 'unix://' + socket;
    const format = '{{.ID}}|{{.OSType}}|{{.Architecture}}|{{.Swarm.LocalNodeState}}|{{.Name}}|{{.KernelVersion}}';
    const [id, type, arch, swarm, host, kernel] = this.call(['info','--format',format]).split('|');
    check(id && type === 'linux' && ['amd64','x86_64'].includes(arch) && swarm === 'inactive' &&
      host === os.hostname() && kernel === os.release(), 'LOCAL_ENGINE_NOT_CONFIRMED');
    this.daemonId = id;
    const version = this.call(['version','--format','{{.Server.Version}}']);
    this.log('preflight', { context: ctx, socket: this.socket, version, platform:'linux/amd64', sameHost:true, sameKernel:true, swarm });
  }
  inspect(type, name, optional = false) {
    const s = this.call([type,'inspect','--format','{{json .}}',name], { optional });
    return s === null ? null : JSON.parse(s);
  }
  createVolume() {
    check(!this.inspect('volume',this.volume,true), 'VOLUME_COLLISION');
    this.volumeIntent = true;
    this.call(['volume','create','--driver','local','--label',owner+'=phase3','--label',runLabel+'='+this.run,this.volume]);
    this.requireVolume();
  }
  requireVolume() {
    const v = this.inspect('volume',this.volume);
    check(v.Name === this.volume && v.Labels?.[owner] === 'phase3' && v.Labels[runLabel] === this.run && v.Driver === 'local' &&
      !Object.keys(v.Options || {}).length, 'VOLUME_OWNERSHIP');
  }
  importImage(a) {
    const tag = 'release-gate.invalid/lab/' + this.prefix + ':' + a.edition;
    const existing = this.inspect('image',a.manifestDigest,true) || this.inspect('image',a.expectedImageId,true);
    let image = existing;
    if (!image) {
      check(!this.inspect('image',tag,true), 'IMAGE_TAG_COLLISION');
      const tar = archive(this.dir,a,tag);
      this.ownedImages.push({tag,a});
      this.call(['image','load','--input',tar], {timeout:45000});
      image = this.inspect('image',tag);
    }
    check([a.manifestDigest, a.expectedImageId].includes(image.Id), 'UNEXPECTED_ENGINE_IMAGE_ID');
    const exported = path.join(this.dir,a.edition+'-engine.tar');
    this.call(['image','save','--output',exported,image.Id], {timeout:45000});
    const checked = spawnSync('python3',['-B',path.join(__dirname,'check_export.py'),exported,a.manifestDigest,a.expectedImageId,image.Id],
      { encoding:'utf8', timeout:10000 });
    check(checked.status === 0, 'ENGINE_EXPORT_MISMATCH');
    const exportedConfig = checked.stdout.trim();
    const binding = bindImage(a,image,exportedConfig);
    this.log('image-binding', { edition:a.edition, verifiedManifestDigest:a.manifestDigest, expectedImageIdFromConfig:a.expectedImageId,
      exportedConfigImageId:exportedConfig, dockerImageId:image.Id, binding, reused:Boolean(existing) });
    return {a, engineId:image.Id, binding};
  }
  launch(role, loaded, health) {
    this.requireVolume();
    const h = {...loaded,role,run:this.run,name:this.prefix+'-'+role,volume:this.volume,nonce:randomUUID()};
    check(!this.inspect('container',h.name,true), 'CONTAINER_COLLISION');
    this.slots.push(h);
    h.id = this.call(['container','create','--name',h.name,'--platform','linux/amd64','--pull=never','--network','none',
      '--read-only','--cap-drop=ALL','--security-opt','no-new-privileges','--user','65532:65532',
      '--pids-limit','64','--memory','96m','--tmpfs','/tmp:rw,noexec,nosuid,nodev,size=4m,mode=1777',
      '--mount','type=volume,source='+this.volume+',target=/state',
      '--label',owner+'=phase3','--label',runLabel+'='+this.run,'--label',roleLabel+'='+role,'--label',nonceLabel+'='+h.nonce,
      '--env','RG_INSTANCE='+h.nonce,'--env','RG_HEALTH='+health,h.engineId]);
    assertContainer(h,this.inspect('container',h.id),{running:false});
    this.call(['container','start',h.id]);
    const running = this.inspect('container',h.id);
    assertContainer(h,running);
    h.containerImageId = running.Image;
    h.hostname = running.Config.Hostname;
    h.containerManifest = running.ImageManifestDescriptor?.digest ?? null;
    this.log('container-started', publicId(h));
    return h;
  }
  http(h, method, route, body = null) {
    const c = this.inspect('container',h.id);
    assertContainer(h,c);
    const value = JSON.parse(this.call(['container','exec',h.id,'/parcel-api','request',method,route,body ? JSON.stringify(body) : ''], {timeout:3000}));
    assertResponse(h,c,value);
    return { ...value, docker: { containerId:c.Id, containerImageId:c.Image, manifest:c.ImageManifestDescriptor?.digest ?? null } };
  }
  cleanup() {
    if (!this.daemonId) return [];
    check(this.call(['info','--format','{{.ID}}']) === this.daemonId, 'DAEMON_CHANGED');
    const problems=[];
    const attempt = (target,operation) => {try{operation();}catch(e){problems.push({target,reason:e.code||e.message});}};
    for (const h of [...this.slots].reverse()) attempt(h.name,()=>{
      const c=this.inspect('container',h.id||h.name,true);
      if (!c) return;
      check(cid.test(c.Id) && (!h.id || h.id === c.Id) && c.Name === '/'+h.name &&
        c.Config?.Labels?.[owner]==='phase3' && c.Config.Labels[runLabel]===this.run &&
        c.Config.Labels[nonceLabel]===h.nonce && c.Config.Labels[roleLabel]===h.role, 'CLEANUP_OWNERSHIP');
      this.call(['container','rm','--force',c.Id]);
    });
    if(this.volumeIntent) attempt(this.volume,()=>{
      if(!this.inspect('volume',this.volume,true)) return;
      this.requireVolume();
      this.call(['volume','rm',this.volume]);
    });
    for(const {tag,a} of this.ownedImages) attempt(tag,()=>{
      const i=this.inspect('image',tag,true);
      if(!i) return;
      check(i.Config?.Labels?.[owner]==='phase3' && i.Config.Labels['io.releasegate.edition']===a.edition &&
        [a.manifestDigest,a.expectedImageId].includes(i.Id) && i.RepoTags?.includes(tag),'CLEANUP_OWNERSHIP');
      this.call(['image','rm','--no-prune',tag]);
    });
    attempt('verify-remaining',()=>{
      check(!this.call(['container','ls','-aq','--filter','label='+runLabel+'='+this.run]) &&
        !this.call(['volume','ls','-q','--filter','label='+runLabel+'='+this.run]), 'RESOURCES_REMAIN');
      for(const {tag} of this.ownedImages) check(!this.inspect('image',tag,true),'TAG_REMAINS');
      this.log('cleanup-verified',{run:this.run,ownedVolume:this.volumeIntent?this.volume:null,
        containerIds:this.slots.map(s=>s.id??null),ownedTags:this.ownedImages.map(i=>i.tag),remainingContainers:[],remainingVolumes:[],remainingTags:[]});
    });
    return problems;
  }
}
function publicId(h) {
  return {role:h.role, containerId:h.id, hostname:h.hostname, approvedImage:h.a.decision.approvedImage,
    verifiedManifestDigest:h.a.manifestDigest, expectedImageIdFromConfig:h.a.expectedImageId,
    dockerImageId:h.engineId, containerImageId:h.containerImageId, containerManifest:h.containerManifest, instance:h.nonce};
}
module.exports={ Engine, assertContainer, assertResponse, localEndpoint, publicId };
