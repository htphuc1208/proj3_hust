"""Bound Docker lifetimes, including when the attached Docker client times out."""
import subprocess
import uuid


def run_container(command, timeout):
    if command[:2] != ['docker', 'run'] or any(arg == '--name' or arg.startswith('--name=') for arg in command):
        raise ValueError('Only unnamed ephemeral docker run commands are accepted')
    name = 'sbom-research-' + uuid.uuid4().hex
    # Mutate the caller's journaled argv so its audit records the actual name.
    command[2:2] = ['--name', name]
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    finally:
        # Killing the docker CLI alone does not guarantee termination of its container.
        # This targets only the unique container created by this invocation.
        subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=20)
