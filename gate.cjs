'use strict';

const { Denial, requireCheck, parseImage, digest } = require('./lib/common.cjs');
const { readImage } = require('./lib/oci.cjs');
const { readPolicyBytes, parsePolicy, enforce } = require('./lib/policy.cjs');
const { verifyImage, verifyProvenance } = require('./lib/sigstore.cjs');

function decide(args, policyRoot) {
  const [reference, target, candidate] = args;
  const result = {
    decision: 'deny', reason: null, message: null, environment: target ?? null, digest: null,
    policyVersion: null, policySha256: null, verificationProfile: 'sigstore-pinned-key-v1',
    imageSignatureVerified: false, provenanceSignatureVerified: false, approvedImage: null,
    imageBundleSha256: null, provenanceBundleSha256: null, verifiedWorkflow: null,
  };
  try {
    let image, referenceError;
    try { image = parseImage(reference); result.digest = image.digest; }
    catch (error) { referenceError = error; }
    const policyBytes = readPolicyBytes(policyRoot);
    result.policySha256 = digest(policyBytes);
    const policy = parsePolicy(policyBytes);
    result.policyVersion = policy.version;
    requireCheck(args.length === 3, 'USAGE', 'Kullanım: node gate.cjs IMAGE@sha256:… ORTAM ADAY_DİZİNİ');
    if (referenceError) throw referenceError;
    const manifest = readImage(candidate, image.digest);
    const imageProof = verifyImage(candidate, manifest, policy);
    result.imageBundleSha256 = imageProof.bundleDigest;
    result.imageSignatureVerified = true;
    const provenance = verifyProvenance(candidate, policy);
    result.provenanceBundleSha256 = provenance.bundleDigest;
    result.verifiedWorkflow = policy.workflow;
    result.provenanceSignatureVerified = true;
    enforce(policy, image, target, provenance.payload);
    return { ...result, decision: 'allow', reason: 'APPROVED', message: 'İki imza ve tüm sürüm onayları doğrulandı.',
      approvedImage: policy.imageRepository + '@' + image.digest };
  } catch (error) {
    result.reason = error instanceof Denial ? error.code : 'GATE_ERROR';
    result.message = error instanceof Denial ? error.message : 'Karar tamamlanamadı.';
    return result;
  }
}

if (require.main === module) {
  const result = decide(process.argv.slice(2));
  console.log(JSON.stringify(result));
  process.exitCode = result.decision === 'allow' ? 0 : 1;
}

module.exports = { decide };
