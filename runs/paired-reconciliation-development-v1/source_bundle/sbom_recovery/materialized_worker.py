"""Container-only stage entrypoint; prediction has no oracle input argument."""
import argparse
import json
from pathlib import Path

from .materialized_scope import capture_inventory,make_npm_lock,match_files,metadata_control,digest
from .storage import save


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("stage",choices=["npm-lock","inspect","predict"])
    parser.add_argument("--ecosystem",choices=["pypi","npm","maven"])
    parser.add_argument("--spec")
    parser.add_argument("--root",default="/out")
    parser.add_argument("--target",default="/target")
    parser.add_argument("--native")
    parser.add_argument("--input")
    parser.add_argument("--out",default="/out")
    args=parser.parse_args()
    if args.stage=="npm-lock":
        spec=json.loads(Path(args.spec).read_text());make_npm_lock(spec,args.root)
        result={"status":"LOCK_PREPARED","instance_count":len(spec["instances"])}
    elif args.stage=="inspect":result=capture_inventory(args.target,args.ecosystem,args.native,args.out)
    else:
        config=json.loads((Path(args.input)/"config.json").read_text())
        catalog_path=Path(args.input)/"catalog.json"
        if digest(catalog_path)!=config["catalog_sha256"]:raise ValueError("Changed public catalog")
        catalog=json.loads(catalog_path.read_text());records=[]
        for scanner in config["scanners"]:
            source=Path(args.input)/scanner["filename"]
            if source.name!=scanner["filename"] or digest(source)!=scanner["sha256"]:raise ValueError("Changed scanner input")
            document=json.loads(source.read_text());bindings=match_files(document,catalog,args.target)
            recovered,control=metadata_control(document,catalog,args.target,bindings)
            base=Path(args.out)/scanner["id"]
            save(base/"bindings.json",bindings);save(base/"recovered.spdx.json",recovered);save(base/"control.json",control)
            records.append({"scanner":scanner["id"],"binding_counts":bindings["counts"],"identity_corrections":len(control["proposals"]),
                            "unknown_metadata":len(control["unresolved"])})
        result={"records":records,"oracle_read":False,"llm_api_calls":0}
    print(json.dumps(result))


if __name__=="__main__":main()
