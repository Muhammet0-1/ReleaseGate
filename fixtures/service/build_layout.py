"""Sentetik linux/amd64 imajlarını yeni bir dizinde üretir. Ağ ve Docker gerekmez."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

MANIFEST = "application/vnd.oci.image.manifest.v1+json"
CONFIG = "application/vnd.oci.image.config.v1+json"
LAYER = "application/vnd.oci.image.layer.v1.tar"
INDEX = "application/vnd.oci.image.index.v1+json"


def json_bytes(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def make_layer(binary):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        entry = tarfile.TarInfo("parcel-note")
        entry.size = len(binary)
        entry.mode = 0o755
        entry.mtime = 0
        archive.addfile(entry, io.BytesIO(binary))
    return out.getvalue()


def build(destination):
    destination.mkdir()  # Var olan dizin veya kanıt üzerine yazılmaz.
    blobs = destination / "oci/blobs/sha256"
    blobs.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="parcel-build-") as tmp:
        exe = Path(tmp) / "parcel-note"
        subprocess.run(["gcc", "-static", "-Os", "-s", "-Wl,--build-id=none",
                        str(Path(__file__).with_name("main.c")), "-o", str(exe)], check=True)
        layer_bytes = make_layer(exe.read_bytes())

    def put(media_type, data):
        hex_digest = hashlib.sha256(data).hexdigest()
        (blobs / hex_digest).write_bytes(data)
        return {"mediaType": media_type, "size": len(data), "digest": "sha256:" + hex_digest}

    layer = put(LAYER, layer_bytes)
    (destination / "oci/oci-layout").write_bytes(json_bytes({"imageLayoutVersion": "1.0.0"}))
    for edition, index_name in [("blue", "oci/index.json"), ("green", "alternate-index.json")]:
        config = {"architecture": "amd64", "os": "linux",
                  "config": {"Entrypoint": ["/parcel-note"], "Env": ["PARCEL_EDITION=" + edition]},
                  "rootfs": {"type": "layers", "diff_ids": [layer["digest"]]}}
        descriptor = put(CONFIG, json_bytes(config))
        manifest = {"schemaVersion": 2, "mediaType": MANIFEST, "config": descriptor, "layers": [layer]}
        entry = put(MANIFEST, json_bytes(manifest))
        entry["annotations"] = {"org.opencontainers.image.ref.name": "candidate"}
        (destination / index_name).write_bytes(json_bytes(
            {"schemaVersion": 2, "mediaType": INDEX, "manifests": [entry]}))
        print(edition, entry["digest"])


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Kullanım: python3 build_layout.py YENİ_ADAY_DİZİNİ")
    build(Path(sys.argv[1]))
