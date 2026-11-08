"""Resource-bounded acquisition/capture helpers; public roots are explicit arguments."""
from pathlib import Path
import shutil
import subprocess

from sbom_recovery.core.research_core import ROOT, load, now, save
from .container_runner import run_container


def capture_installation(specifications, destination, image):
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    code = destination.parent / "capture_code"
    code.mkdir(exist_ok=True)
    shutil.copyfile(ROOT / "benchmark.py", code / "benchmark.py")
    shutil.copyfile(ROOT / "scripts/capture_environment.py", code / "capture_environment.py")
    args = ["docker", "run", "--rm", "--cap-drop=ALL", "--security-opt", "no-new-privileges", "--memory=2g", "--cpus=2",
            "--pids-limit=128", "--user", "1000:1000", "-v", f"{code}:/code:ro", "-v", f"{destination}:/out:rw",
            "--entrypoint", "python", image, "/code/capture_environment.py", "--out", "/out"]
    for spec in specifications:
        args.extend(["--spec", spec])
    started = now()
    result = run_container(args, timeout=1200)
    (destination / "container.log").write_text(result.stdout + result.stderr)
    manifest = load(destination / "capture_manifest.json") if (destination / "capture_manifest.json").exists() else {}
    manifest.update(container_command=args, image=image, container_started_at=started, container_completed_at=now())
    if result.returncode:
        manifest.update(status="BLOCKED", technical_cause=result.stdout + result.stderr)
    save(destination / "capture_manifest.json", manifest)
    return manifest
