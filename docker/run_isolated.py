#!/usr/bin/env python3
"""Runner for containerized benchmark collection.

Runs target package installations inside an ephemeral Docker container
with dropped capabilities and restricted filesystem mounts to protect host.
"""
import argparse
from pathlib import Path
import subprocess
import sys

IMAGE_NAME = "sbom-benchmark-harness:3.11"
ROOT = Path(__file__).resolve().parents[1]


def build_image_if_needed():
    res = subprocess.run(["docker", "image", "inspect", IMAGE_NAME], capture_output=True)
    if res.returncode != 0:
        print(f"[*] Building isolated benchmark image {IMAGE_NAME}...")
        subprocess.run([
            "docker", "build",
            "-f", str(ROOT / "docker" / "Dockerfile.harness"),
            "-t", IMAGE_NAME,
            str(ROOT)
        ], check=True)


def run_collection(package_spec: str, project_id: str, output_dir: Path):
    build_image_if_needed()
    out = Path(output_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)

    cmd = (
        f"python -m venv /tmp/venv && "
        f"/tmp/venv/bin/python -m pip install --report /out/pip_install_report.json '{package_spec}' && "
        f"python /benchmark/benchmark.py collect "
        f"--python /tmp/venv/bin/python "
        f"--install-report /out/pip_install_report.json "
        f"--project '{project_id}' "
        f"--root '{package_spec}' "
        f"--out /out"
    )

    docker_args = [
        "docker", "run", "--rm",
        "--cap-drop=ALL",
        "--memory=2g",
        "--cpus=2.0",
        "-v", f"{ROOT}:/benchmark:ro",
        "-v", f"{out}:/out:rw",
        "--user", "1000:1000",
        "--entrypoint", "/bin/bash",
        IMAGE_NAME,
        "-c", cmd
    ]
    print(f"[*] Executing isolated container run for {package_spec}...")
    subprocess.run(docker_args, check=True)
    print(f"[OK] Container collection finished. Artifacts saved to {out}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", required=True, help="e.g. requests==2.31.0")
    parser.add_argument("--project", required=True, help="Project identifier")
    parser.add_argument("--out", type=Path, required=True, help="Output directory")
    args = parser.parse_args()
    run_collection(args.package, args.project, args.out)
