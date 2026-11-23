'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { decide } = require('../gate.cjs');
const { readImage } = require('../lib/oci.cjs');
const { digest, readFileBelow } = require('../lib/common.cjs');
const { check, Failure } = require('../phase2/http.cjs');

const fixture = path.join(__dirname, 'fixture');
const releases = {
  blue: 'registry.example.invalid/workshop/parcel-note@sha256:112f352ce79f51898c288f3141061f5ad40ddfdcde7a4f872a61dedb70c0f09d',
  green: 'registry.example.invalid/workshop/parcel-note@sha256:669bb9556bdddc739f0d6ab504bc8588acaa9afe347f546182c903a7782dbea8',
};
function policy(name) { return path.join(__dirname, 'policies', name); }

function stage(dir, edition) {
  const input = path.join(dir, edition);
  fs.mkdirSync(input, { mode: 0o700 });
  fs.cpSync(path.join(fixture, 'oci'), path.join(input, 'oci'), { recursive: true });
  for (const name of ['image.sigstore.json', 'provenance.sigstore.json']) {
    fs.copyFileSync(path.join(fixture, edition, name), path.join(input, name), fs.constants.COPYFILE_EXCL);
  }
  return input;
}

function verified(input, edition, policyDir, log) {
  const decision = decide([releases[edition], 'test', input], policyDir);
  log('gate', { edition, decision });
  if (decision.decision !== 'allow') throw new Failure(decision.reason);
  const manifest = readImage(input, decision.digest);
  const doc = JSON.parse(manifest);
  function bytes(desc, limit) {
    const data = readFileBelow(input, 'oci/blobs/sha256/' + desc.digest.slice(7), limit);
    check(data.length === desc.size && digest(data) === desc.digest, 'BLOB_CHANGED');
    return data;
  }
  const config = bytes(doc.config, 1024 * 1024);
  const layer = bytes(doc.layers[0], 16 * 1024 * 1024);
  const parsed = JSON.parse(config);
  check(parsed.config.Labels['io.releasegate.project'] === 'phase3' && parsed.config.Labels['io.releasegate.edition'] === edition &&
    parsed.config.Entrypoint.length === 1 && parsed.config.Entrypoint[0] === '/parcel-api' &&
    parsed.config.User === '65532:65532' && !parsed.config.Volumes && !parsed.config.ExposedPorts,
    'IMAGE_PROFILE_MISMATCH');
  return { edition, decision, manifest, config, layer, manifestDigest: decision.digest,
    expectedImageId: digest(config), layerDigest: digest(layer) };
}

// Docker arşivi yalnız az önce özetlenen baytlardan kurulur. İndekste tek platform ve tek görev etiketi vardır.
function archive(work, a, tag) {
  const dir = path.join(work, 'load-' + a.edition);
  const blobs = path.join(dir, 'blobs/sha256');
  fs.mkdirSync(blobs, { recursive: true });
  for (const [id, bytes] of [[a.manifestDigest, a.manifest], [a.expectedImageId, a.config], [a.layerDigest, a.layer]]) {
    fs.writeFileSync(path.join(blobs, id.slice(7)), bytes, { flag: 'wx' });
  }
  const name = id => 'blobs/sha256/' + id.slice(7);
  const index = { schemaVersion: 2, mediaType: 'application/vnd.oci.image.index.v1+json', manifests: [{
    mediaType: 'application/vnd.oci.image.manifest.v1+json', size: a.manifest.length, digest: a.manifestDigest,
    platform: { os: 'linux', architecture: 'amd64' }, annotations: {
      'io.containerd.image.name': tag, 'org.opencontainers.image.ref.name': tag,
    } }] };
  for (const [n, v] of [['oci-layout', { imageLayoutVersion: '1.0.0' }], ['index.json', index],
    ['manifest.json', [{ Config: name(a.expectedImageId), RepoTags: [tag], Layers: [name(a.layerDigest)] }]]]) {
    fs.writeFileSync(path.join(dir, n), JSON.stringify(v), { flag: 'wx' });
  }
  const file = path.join(work, a.edition + '-load.tar');
  const proc = spawnSync('tar', ['--format=ustar','-cf',file,'-C',dir,'index.json','oci-layout','manifest.json','blobs']);
  check(proc.status === 0, 'ARCHIVE_FAILED');
  return file;
}

function bindImage(a, image, exportedConfig) {
  check(exportedConfig === a.expectedImageId && image.Os === 'linux' && image.Architecture === 'amd64' &&
    image.Config?.Labels?.['io.releasegate.project'] === 'phase3' && image.Config.Labels['io.releasegate.edition'] === a.edition &&
    image.RootFS?.Layers?.length === 1 && image.RootFS.Layers[0] === a.layerDigest, 'IMAGE_ID_MISMATCH');
  const descriptor = image.Descriptor;
  const signedManifest = descriptor?.digest === a.manifestDigest &&
    descriptor.mediaType === 'application/vnd.oci.image.manifest.v1+json';
  if (image.Id === a.expectedImageId) {
    check(!descriptor || signedManifest, 'IMAGE_ID_MISMATCH');
    return 'config-id';
  }
  check(image.Id === a.manifestDigest && signedManifest, 'IMAGE_ID_MISMATCH');
  return 'single-manifest-id';
}

module.exports = { stage, verified, policy, archive, bindImage, releases };
