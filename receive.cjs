'use strict';

// Yalnız CI'daki kapı çıktısı bu yerel tüketiciye bağlanır.
const fs = require('node:fs');
const { parseImage, requireCheck, Denial, digest } = require('./lib/common.cjs');
const { readPolicyBytes, parsePolicy } = require('./lib/policy.cjs');
const { readImage } = require('./lib/oci.cjs');

try {
  const decision = JSON.parse(fs.readFileSync(0, 'utf8'));
  requireCheck(process.argv.length === 3 && decision?.decision === 'allow' && decision.reason === 'APPROVED' &&
    decision.environment === 'test' && decision.imageSignatureVerified === true && decision.provenanceSignatureVerified === true,
    'NO_APPROVAL', 'Tüketiciye başarılı bir test ortamı kararı gelmedi.');
  const image = parseImage(decision.approvedImage);
  requireCheck(image.digest === decision.digest, 'HANDOFF_DIGEST', 'Teslim referansı kararın digest değeriyle uyuşmuyor.');
  const policyBytes = readPolicyBytes();
  const policy = parsePolicy(policyBytes);
  requireCheck(decision.policySha256 === digest(policyBytes) && decision.policyVersion === policy.version &&
    decision.environment === policy.environment && image.repository === policy.imageRepository && image.digest === policy.approvedDigest,
    'HANDOFF_POLICY', 'Teslim kaydı kurulu politikanın onaylı sürümüne uymuyor.');
  readImage(process.argv[2], image.digest);
  console.log(JSON.stringify({ stage: 'dry-run', environment: 'test', receivedImage: decision.approvedImage, digest: image.digest }));
} catch (error) {
  console.error(JSON.stringify({ stage: 'handoff-denied', reason: error instanceof Denial ? error.code : 'INVALID_HANDOFF' }));
  process.exitCode = 1;
}
