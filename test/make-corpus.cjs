'use strict';

// Yalnız sentetik kanıt üretir. Operatörün onay politikasını okumaz veya yazmaz.
const fs = require('node:fs');
const path = require('node:path');
const { generateKeyPairSync, sign } = require('node:crypto');
const { sigstore } = require('../lib/dependencies.cjs');
const { digest } = require('../lib/common.cjs');
const { MessageSignatureBundleBuilder, DSSEBundleBuilder } = sigstore('@sigstore/sign');
const { bundleToJSON } = sigstore('@sigstore/bundle');

const repository = 'registry.example.invalid/workshop/parcel-note';
const source = 'git+https://forge.example.invalid/workshop/parcel-note.git';
const commit = '2e3a18cf671482b07e787646f926417f575b6a03';
const workflow = 'https://build.example.invalid/workflows/parcel-release@c79cc7c72b2197b9b8bd0bb5304dea959fe74a86';

function signer(identity) {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const pem = publicKey.export({ type: 'spki', format: 'pem' });
  return {
    pem,
    sign: async bytes => ({
      signature: sign('sha256', bytes, privateKey),
      key: { $case: 'publicKey', publicKey: pem, hint: identity },
    }),
  };
}

function statement(manifest) {
  return {
    _type: 'https://in-toto.io/Statement/v1',
    subject: [{ name: repository, digest: { sha256: digest(manifest).slice(7) } }],
    predicateType: 'https://slsa.dev/provenance/v1',
    predicate: {
      buildDefinition: {
        buildType: 'https://build.example.invalid/types/parcel-oci/v1',
        externalParameters: { repository: source, workflow, targetEnvironment: 'test' },
        resolvedDependencies: [{ uri: source, digest: { gitCommit: commit } }],
      },
      runDetails: { builder: { id: 'https://build.example.invalid/builders/parcel/v1' } },
    },
  };
}

async function corpus(candidate, output) {
  fs.mkdirSync(output);
  const save = (name, value) => fs.writeFileSync(path.join(output, name), JSON.stringify(value, null, 2) + '\n', { flag: 'wx' });
  const publisher = signer('parcel-note-publisher');
  const builder = signer(workflow);
  const outsider = signer(workflow); // Aynı kimliği beyan eden farklı anahtar.
  const dsse = async (payload, key = builder, type = 'application/vnd.in-toto+json') => {
    const bundler = new DSSEBundleBuilder({ signer: key, witnesses: [] });
    return bundleToJSON(await bundler.create({ data: Buffer.from(payload), type }));
  };
  const attest = s => dsse(JSON.stringify(s));
  const imageSignature = async (manifest, key = publisher) => {
    const bundler = new MessageSignatureBundleBuilder({ signer: key, witnesses: [] });
    return bundleToJSON(await bundler.create({ data: manifest }));
  };
  function manifestAt(indexPath) {
    const index = JSON.parse(fs.readFileSync(path.join(candidate, indexPath)));
    const hex = index.manifests[0].digest.slice(7);
    return fs.readFileSync(path.join(candidate, 'oci/blobs/sha256', hex));
  }
  const blue = manifestAt('oci/index.json');
  const green = manifestAt('alternate-index.json');
  const good = statement(blue);
  save('public-keys.json', { publisherKey: publisher.pem, workflowKey: builder.pem });
  save('image.sigstore.json', await imageSignature(blue));
  save('provenance.sigstore.json', await attest(good));
  const changes = {
    wrongCommit: s => { s.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit = 'a'.repeat(40); },
    wrongWorkflow: s => { s.predicate.buildDefinition.externalParameters.workflow = 'https://build.example.invalid/workflows/debug'; },
    wrongBuilder: s => { s.predicate.runDetails.builder.id = 'https://build.example.invalid/builders/other'; },
    wrongRepository: s => { s.predicate.buildDefinition.externalParameters.repository = 'git+https://forge.example.invalid/other.git'; },
    wrongBuildType: s => { s.predicate.buildDefinition.buildType = 'https://build.example.invalid/types/debug'; },
    wrongEnvironment: s => { s.predicate.buildDefinition.externalParameters.targetEnvironment = 'prod'; },
    differentMaterial: s => { s.predicate.buildDefinition.resolvedDependencies[0].uri = 'git+https://forge.example.invalid/other.git'; },
    missingCommit: s => { delete s.predicate.buildDefinition.resolvedDependencies[0].digest; },
    extraInput: s => { s.predicate.buildDefinition.externalParameters.extra = 'unapproved'; },
    differentSubject: s => { s.subject[0].digest.sha256 = digest(green).slice(7); },
    differentSubjectName: s => { s.subject[0].name = 'registry.example.invalid/workshop/other'; },
    extraSubject: s => { s.subject.push({ name: 'extra', digest: { sha256: '0'.repeat(64) } }); },
    otherPredicate: s => { s.predicateType = 'https://example.invalid/other/v1'; },
  };
  const provenance = {};
  for (const [label, mutate] of Object.entries(changes)) {
    const s = structuredClone(good);
    mutate(s);
    provenance[label] = await attest(s);
  }
  provenance.foreignKey = await dsse(JSON.stringify(good), outsider);
  provenance.invalidJson = await dsse('{');
  provenance.otherMediaType = await dsse(JSON.stringify(good), builder, 'application/json');
  save('variants.json', {
    provenance,
    alternate: { image: await imageSignature(green), provenance: await attest(statement(green)) },
    foreignPublisher: await imageSignature(blue, signer('parcel-note-publisher')),
  });
}

if (process.argv.length !== 4) throw new Error('Kullanım: node test/make-corpus.cjs ADAY_DİZİNİ YENİ_ÇIKTI');
corpus(process.argv[2], process.argv[3]).catch(error => { console.error(error.message); process.exitCode = 1; });
