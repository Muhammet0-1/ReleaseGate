'use strict';

const { digest, digestPattern, parseJSON, readFileBelow, requireCheck, Denial } = require('./common.cjs');

const manifestType = 'application/vnd.oci.image.manifest.v1+json';
const configType = 'application/vnd.oci.image.config.v1+json';
const layerType = 'application/vnd.oci.image.layer.v1.tar';
const metadataLimit = 1024 * 1024;
const blobLimit = 16 * 1024 * 1024;

function blob(root, id, limit) {
  requireCheck(typeof id === 'string' && id.length === 71 && digestPattern.test(id),
    'OCI_DESCRIPTOR', 'OCI tanımlayıcısında geçerli bir SHA-256 gerekli.');
  const bytes = readFileBelow(root, 'oci/blobs/sha256/' + id.slice(7), limit);
  requireCheck(digest(bytes) === id, 'OCI_DIGEST', 'Yerel blob içeriği istenen digest ile uyuşmuyor.');
  return bytes;
}

function descriptor(root, desc, types, limit) {
  requireCheck(types.includes(desc?.mediaType) && Number.isSafeInteger(desc.size) && desc.size > 0 && desc.size <= limit,
    'OCI_DESCRIPTOR', 'OCI blob türü veya tanımlayıcı boyutu geçersiz.');
  const bytes = blob(root, desc.digest, limit);
  requireCheck(bytes.length === desc.size, 'OCI_SIZE', 'Blob boyutu imzalanacak manifest ile uyuşmuyor.');
  return bytes;
}

// Etiket dizini kullanılmaz. Hem kapı hem teslim alan süreç içeriği digest ile açar.
function readImage(root, id) {
  try {
    const layout = parseJSON(readFileBelow(root, 'oci/oci-layout', 4096));
    requireCheck(layout?.imageLayoutVersion === '1.0.0', 'OCI_LAYOUT', 'OCI yerleşimi okunamadı.');
    const bytes = blob(root, id, metadataLimit);
    const manifest = parseJSON(bytes);
    requireCheck(manifest?.schemaVersion === 2 && manifest.mediaType === manifestType &&
      Array.isArray(manifest.layers) && manifest.layers.length === 1,
      'OCI_MANIFEST', 'Bu servis tek katmanlı bir OCI imaj manifesti gerektirir.');
    const config = parseJSON(descriptor(root, manifest.config, [configType], metadataLimit));
    requireCheck(config?.os === 'linux' && config.architecture === 'amd64' && config.rootfs?.type === 'layers' &&
      Array.isArray(config.rootfs.diff_ids) && config.rootfs.diff_ids.length === 1 &&
      typeof config.rootfs.diff_ids[0] === 'string' && config.rootfs.diff_ids[0].length === 71 &&
      digestPattern.test(config.rootfs.diff_ids[0]), 'OCI_CONFIG', 'Servis için linux/amd64 katman yapılandırması geçersiz.');
    const layer = manifest.layers[0];
    descriptor(root, layer, [layerType], blobLimit);
    requireCheck(config.rootfs.diff_ids[0] === layer.digest, 'OCI_CONFIG', 'Açık tar katmanının diff_id değeri uyuşmuyor.');
    return bytes;
  } catch (error) {
    if (error instanceof Denial) throw error;
    throw new Denial('OCI_UNREADABLE', 'Gerekli OCI dosyası eksik, bozuk veya okunamıyor.');
  }
}

module.exports = { readImage };
