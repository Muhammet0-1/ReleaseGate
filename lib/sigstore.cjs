'use strict';

const { Denial, requireCheck, readFileBelow, parseJSON, digest } = require('./common.cjs');
const { sigstore } = require('./dependencies.cjs');

function canonicalBase64(value) {
  return typeof value === 'string' && value.length > 0 && Buffer.from(value, 'base64').toString('base64') === value;
}

// Bu profil yalnızca operatörün sabitlediği iki açık anahtara güvenir.
function verify(root, filename, kind, identity, publicKey, manifest) {
  const bundleAPI = sigstore('@sigstore/bundle');
  const { toSignedEntity, toTrustMaterial, Verifier } = sigstore('@sigstore/verify');
  const isImage = kind === 'messageSignature';
  const code = isImage ? 'IMAGE_SIGNATURE' : 'PROVENANCE_SIGNATURE';
  try {
    const bytes = readFileBelow(root, filename, 1024 * 1024);
    const raw = parseJSON(bytes);
    const contentKinds = ['messageSignature', 'dsseEnvelope'].filter(k => Object.hasOwn(raw, k));
    const keyKinds = ['publicKey', 'certificate', 'x509CertificateChain'].filter(k => Object.hasOwn(raw.verificationMaterial, k));
    requireCheck(contentKinds.length === 1 && contentKinds[0] === kind && keyKinds.length === 1 && keyKinds[0] === 'publicKey',
      code, 'Kanıt beklenen Sigstore paket türü ve anahtar profiline uymuyor.');
    const packet = raw[kind];
    const encoded = isImage ? [packet.signature, packet.messageDigest?.digest] : [packet.payload, packet.signatures?.[0]?.sig];
    requireCheck(encoded.every(canonicalBase64), code, 'Paketteki imza, yük veya digest geçerli standart Base64 olmalı.');
    const bundle = bundleAPI.bundleFromJSON(raw);
    requireCheck([bundleAPI.BUNDLE_V02_MEDIA_TYPE, bundleAPI.BUNDLE_V03_MEDIA_TYPE].includes(bundle.mediaType) &&
      bundle.verificationMaterial.content.publicKey.hint === identity,
      code, 'Kanıt bu rol için sabitlenmiş imzalayan kimliğine uymuyor.');
    if (isImage) {
      const claimed = bundle.content.messageSignature.messageDigest;
      requireCheck(packet.messageDigest.algorithm === 'SHA2_256' &&
        digest(manifest) === 'sha256:' + Buffer.from(claimed.digest).toString('hex'),
        code, 'İmza paketindeki digest ham OCI manifestine uymuyor.');
    } else {
      requireCheck(bundle.content.dsseEnvelope.payloadType === 'application/vnd.in-toto+json',
        'PROVENANCE_TYPE', 'İmzalı zarf in-toto belge türünde olmalı.');
    }

    const keys = Object.create(null);
    keys[identity] = { rawBytes: publicKey.export({ type: 'spki', format: 'der' }) };
    const trust = toTrustMaterial({ certificateAuthorities: [], timestampAuthorities: [], tlogs: [], ctlogs: [] }, keys);
    // Çevrimdışı sabit anahtarlar için şeffaflık günlüğü veya zaman damgası aranmaz.
    const verifier = new Verifier(trust, { tlogThreshold: 0, timestampThreshold: 0 });
    verifier.verify(toSignedEntity(bundle, manifest));
    return { bundleDigest: digest(bytes), payload: bundle.content.dsseEnvelope?.payload };
  } catch (error) {
    if (error instanceof Denial) throw error;
    throw new Denial(code, isImage ? 'İmaj imzası okunamadı veya sabit açık anahtarla doğrulanamadı.'
      : 'Köken imzası okunamadı veya iş akışının sabit açık anahtarıyla doğrulanamadı.');
  }
}

function verifyImage(root, manifest, policy) {
  return verify(root, 'image.sigstore.json', 'messageSignature', 'parcel-note-publisher', policy.publisherKey, manifest);
}

function verifyProvenance(root, policy) {
  return verify(root, 'provenance.sigstore.json', 'dsseEnvelope', policy.workflow, policy.workflowKey);
}

module.exports = { verifyImage, verifyProvenance };
