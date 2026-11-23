'use strict';

const { createPublicKey } = require('node:crypto');
const path = require('node:path');
const { isDeepStrictEqual } = require('node:util');
const { Denial, requireCheck, parseJSON, parseImage, exactKeys, readFileBelow } = require('./common.cjs');

const required = [
  'schemaVersion', 'version', 'environment', 'imageRepository', 'approvedDigest', 'sourceRepository',
  'approvedCommit', 'buildType', 'builderId', 'workflow', 'publisherKey', 'workflowKey',
];

function readPolicyBytes(root = path.resolve(__dirname, '../policy')) {
  try { return readFileBelow(root, 'test.json', 64 * 1024); }
  catch { throw new Denial('POLICY_INVALID', 'Bağımsız politika dosyası okunamıyor.'); }
}

function parsePolicy(bytes) {
  try {
    const p = parseJSON(bytes);
    const validStrings = exactKeys(p, required) && required.slice(1).every(k => typeof p[k] === 'string' && p[k].length > 0);
    if (!validStrings || p.schemaVersion !== 1 || !/^[A-Za-z0-9._-]{1,64}$/.test(p.version) ||
        p.environment !== 'test' || p.approvedCommit.length !== 40 || !/^[a-f0-9]{40}$/.test(p.approvedCommit) ||
        !p.sourceRepository.startsWith('git+https://') || ![p.buildType, p.builderId, p.workflow].every(v => v.startsWith('https://'))) {
      throw new Error('Şema uyuşmazlığı.');
    }
    parseImage(p.imageRepository + '@' + p.approvedDigest);
    for (const field of ['publisherKey', 'workflowKey']) {
      if (!p[field].startsWith('-----BEGIN PUBLIC KEY-----')) throw new Error('Açık anahtar bekleniyor.');
      p[field] = createPublicKey(p[field]);
      if (p[field].asymmetricKeyType !== 'ec' || p[field].asymmetricKeyDetails.namedCurve !== 'prime256v1') {
        throw new Error('P-256 anahtarı bekleniyor.');
      }
    }
    if (p.publisherKey.equals(p.workflowKey)) throw new Error('Roller ayrı anahtar gerektirir.');
    return p;
  } catch {
    throw new Denial('POLICY_INVALID', 'Güvenilir onay politikası eksik veya geçersiz.');
  }
}

// Bu fonksiyon yalnız doğrulayıcının döndürdüğü aynı DSSE yükünü değerlendirir.
function enforce(policy, image, target, payload) {
  let statement;
  try { statement = parseJSON(payload); } catch { throw new Denial('STATEMENT_INVALID', 'İmzalı içerik geçerli JSON değil.'); }
  requireCheck(statement?._type === 'https://in-toto.io/Statement/v1' &&
    statement.predicateType === 'https://slsa.dev/provenance/v1', 'STATEMENT_TYPE', 'in-toto v1 ve SLSA Build Provenance v1 gerekli.');
  requireCheck(image.repository === policy.imageRepository, 'IMAGE_REPOSITORY', 'İmaj deposu onaylı servisle uyuşmuyor.');
  requireCheck(isDeepStrictEqual(statement.subject, [{ name: image.repository, digest: { sha256: image.digest.slice(7) } }]),
    'SUBJECT_MISMATCH', 'İmzalı köken belgesi tam olarak istenen imajı ve digest değerini göstermiyor.');
  requireCheck(image.digest === policy.approvedDigest, 'DIGEST_NOT_APPROVED', 'Bu manifest digest’i politikada onaylanmamış.');
  requireCheck(target === policy.environment, 'TARGET_ENVIRONMENT', 'Talep edilen hedef ortam bu politika için onaylı değil.');
  const definition = statement.predicate?.buildDefinition;
  requireCheck(statement.predicate?.runDetails?.builder?.id === policy.builderId, 'BUILDER_ID', 'İmzalı builder kimliği onaylı değil.');
  requireCheck(definition?.buildType === policy.buildType, 'BUILD_TYPE', 'İmzalı build türü onaylı değil.');
  const params = definition.externalParameters;
  requireCheck(exactKeys(params, ['repository', 'workflow', 'targetEnvironment']),
    'BUILD_INPUTS', 'İmzalı dış build parametrelerinin listesi beklenenden farklı.');
  requireCheck(params.repository === policy.sourceRepository, 'SOURCE_REPOSITORY', 'İmzalı kaynak depo onaylı değil.');
  requireCheck(params.workflow === policy.workflow, 'WORKFLOW_ID', 'İmzalı iş akışı kimliği anahtara bağlı onayla uyuşmuyor.');
  requireCheck(params.targetEnvironment === target, 'BUILD_ENVIRONMENT', 'İmzalı build hedefi ile istenen ortam uyuşmuyor.');
  const deps = definition.resolvedDependencies;
  requireCheck(Array.isArray(deps) && deps.length === 1 && deps[0]?.uri === policy.sourceRepository,
    'SOURCE_MATERIAL', 'Çözümlenen kaynak tek ve onaylı depo olmalı.');
  requireCheck(isDeepStrictEqual(deps[0].digest, { gitCommit: policy.approvedCommit }),
    'COMMIT_NOT_APPROVED', 'İmzalı kaynak commit’i bağımsız onayla uyuşmuyor.');
}

module.exports = { readPolicyBytes, parsePolicy, enforce };
