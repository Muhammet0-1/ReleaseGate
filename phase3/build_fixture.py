"""Çevrimdışı Faz 1 katmanını ve yeni Unix HTTP servisini tek OCI katmanında paketler."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BASE = "b047fd3f525ad40552115bf19e02562c3c99a2fa4cf7ed2be2277f5664eb95a4"
PREFIX = "application/vnd.oci.image."


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def build(output):
    output.mkdir()
    blobs = output / "oci/blobs/sha256"
    blobs.mkdir(parents=True)
    original = (ROOT / "fixtures/candidate/oci/blobs/sha256" / BASE).read_bytes()
    if hashlib.sha256(original).hexdigest() != BASE:
        raise ValueError("Faz 1 katman özeti değişmiş")
    with tarfile.open(fileobj=io.BytesIO(original), mode="r:") as base:
        entry = base.getmember("parcel-note")
        if not entry.isfile(): raise ValueError("Eksik base servisi")
        base_binary = base.extractfile(entry).read()
    with tempfile.TemporaryDirectory(prefix="rg3-build-") as tmp:
        temp = Path(tmp)
        env = dict(os.environ, GOENV="off", GO111MODULE="off", GOTOOLCHAIN="local", GOPROXY="off",
                   GOSUMDB="off", CGO_ENABLED="0", GOOS="linux", GOARCH="amd64", GOAMD64="v1",
                   GOFLAGS="", GOWORK="off", GOPATH=str(temp/"gopath"), GOCACHE=str(temp/"cache"))
        subprocess.run(["go","build","-trimpath","-buildvcs=false","-ldflags=-s -w -buildid=",
                        "-o",str(temp/"api"),str(ROOT/"phase3/service/main.go")],check=True,env=env)
        api = (temp/"api").read_bytes()
    packed = io.BytesIO()
    with tarfile.open(fileobj=packed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, payload in [("parcel-note",base_binary),("parcel-api",api),("state",None),
                              ("state/data",None),("state/data/.format",b"parcel-record-v1\n")]:
            e = tarfile.TarInfo(name)
            e.mode = 0o755 if payload is None or name.startswith("parcel-") else 0o600
            e.uid = e.gid = 65532 if name.startswith("state") else 0
            if payload is None:
                e.type = tarfile.DIRTYPE
                archive.addfile(e)
            else:
                e.size = len(payload)
                archive.addfile(e,io.BytesIO(payload))

    def blob(kind, data):
        hx = hashlib.sha256(data).hexdigest()
        (blobs/hx).write_bytes(data)
        return {"mediaType":PREFIX+kind,"digest":"sha256:"+hx,"size":len(data)}

    layer = blob("layer.v1.tar",packed.getvalue())
    (output/"oci/oci-layout").write_bytes(encode({"imageLayoutVersion":"1.0.0"}))
    for edition, index in [("blue","oci/index.json"),("green","alternate-index.json")]:
        config = {"architecture":"amd64","os":"linux","config":{"Entrypoint":["/parcel-api"],"User":"65532:65532",
                  "Env":["PARCEL_EDITION="+edition],"Labels":{"io.releasegate.project":"phase3","io.releasegate.edition":edition}},
                  "rootfs":{"type":"layers","diff_ids":[layer["digest"]]}}
        cd = blob("config.v1+json",encode(config))
        manifest = {"schemaVersion":2,"mediaType":PREFIX+"manifest.v1+json","config":cd,"layers":[layer]}
        md = blob("manifest.v1+json",encode(manifest))
        (output/index).write_bytes(encode({"schemaVersion":2,"mediaType":PREFIX+"index.v1+json","manifests":[md]}))
        print(edition, md["digest"],cd["digest"])


if __name__=="__main__":
    if len(sys.argv)!=2: raise SystemExit("Kullanım: python3 phase3/build_fixture.py YENİ_DİZİN")
    build(Path(sys.argv[1]))
