"""Yalnız Docker'ın seçili imaj için dışarı verdiği arşivi okur. Dosya çıkartmaz."""
import hashlib
import json
import re
import sys
import tarfile


def verify(archive, manifest_id, config_id, engine_id):
    for value in (manifest_id, config_id, engine_id):
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", value): raise ValueError("invalid id")
    if engine_id not in (manifest_id, config_id): raise ValueError("unknown engine id")
    with tarfile.open(archive, "r:") as tar:
        names = {}
        for item in tar:
            if item.name in names: raise ValueError("duplicate member")
            names[item.name] = item

        def read(name):
            m = names[name]
            if not m.isfile() or not 0 < m.size <= 1024*1024: raise ValueError("invalid member")
            return tar.extractfile(m).read()

        def sha(data):
            return "sha256:" + hashlib.sha256(data).hexdigest()

        manifest_path = "blobs/sha256/"+manifest_id[7:]
        if manifest_path in names:
            raw = read(manifest_path)
            index = json.loads(read("index.json"))
            targets = index.get("manifests", [])
            if index.get("schemaVersion") != 2 or len(targets) != 1:
                raise ValueError("ambiguous engine index")
            target = targets[0]
            if (target.get("mediaType") != "application/vnd.oci.image.manifest.v1+json"
                    or target.get("digest") != manifest_id or target.get("size") != len(raw)):
                raise ValueError("engine index points to a different manifest")
            config_desc = json.loads(raw)["config"]
            if sha(raw) != manifest_id or config_desc["digest"] != config_id:
                raise ValueError("wrong manifest/config")
            config = read("blobs/sha256/"+config_id[7:])
            if len(config) != config_desc["size"]:
                raise ValueError("wrong config size")
        elif engine_id == config_id:
            entries = json.loads(read("manifest.json"))
            if len(entries) != 1: raise ValueError("ambiguous classic archive")
            config = read(entries[0]["Config"])
        else:
            raise ValueError("engine manifest bytes missing")
        if sha(config) != config_id: raise ValueError("exported config mismatch")
        return sha(config)


if __name__ == "__main__":
    print(verify(*sys.argv[1:]))
