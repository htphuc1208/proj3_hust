"""Container-only static analysis and benign CVE-2020-14343 witness.

No package code is imported by the host controller. Runtime observations never
enter the static analyzer. Only the fixed arithmetic expression is evaluated.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time


EXPRESSION = "40 + 2"
PAYLOAD = ('!!python/object/new:tuple\n- !!python/object/new:map\n'
           '  - !!python/name:eval\n  - ["40 + 2"]\n')
ORDINARY = "answer: 42\n"


def code_signature(code):
    return {"bytecode": code.co_code.hex(), "constants": repr(code.co_consts),
            "names": list(code.co_names), "filename": code.co_filename,
            "name": code.co_name, "flags": code.co_flags}


def runtime(root, version, input_kind, *, audit_control=False):
    # Preload all instrumentation before arming. No eval monkeypatch or custom
    # YAML constructor is installed; both library source trees remain pristine.
    sys.path.insert(0, str(root))
    app = importlib.import_module("app")
    yaml = importlib.import_module("yaml")
    origin = Path(yaml.__file__).resolve()
    if yaml.__version__ != version or origin != root / "yaml/__init__.py":
        raise ValueError("Unexpected YAML source/version")
    # Compile without inheriting module flags to match PyYAML eval behavior
    expected_code = compile(EXPRESSION, "<string>", "eval", dont_inherit=True)
    expected_signature = code_signature(expected_code)
    events, calls = [], []
    armed = False

    def stack():
        frame = sys._getframe(2)
        result = []
        while frame:
            filename = frame.f_code.co_filename
            if filename.startswith(str(root) + "/"):
                result.append({"file": str(Path(filename).relative_to(root)),
                               "function": frame.f_code.co_qualname,
                               "line": frame.f_lineno})
            frame = frame.f_back
        return result

    def audit(event, arguments):
        if not armed:
            return
        if event == "compile":
            source = arguments[0]
            if isinstance(source, str):
                source = source.encode("utf-8")
            if source == EXPRESSION.encode():
                events.append({"event": "compile", "sequence": len(events),
                               "source_sha256": hashlib.sha256(source).hexdigest(),
                               "filename": arguments[1], "stack": stack()})
        elif event == "exec":
            # Record all exec events in scope for diagnostic purposes
            code_obj = arguments[0]
            signature = code_signature(code_obj)
            in_scope = code_obj.co_filename.startswith(str(root) + "/") or code_obj.co_filename == "<string>"
            if in_scope:
                events.append({"event": "exec", "sequence": len(events),
                               "signature": signature,
                               "matches_expected": signature == expected_signature,
                               "stack": stack()})

    def profile(frame, event, argument):
        if event == "call" and frame.f_code.co_filename.startswith(str(root) + "/"):
            calls.append({"file": str(Path(frame.f_code.co_filename).relative_to(root)),
                          "function": frame.f_code.co_qualname,
                          "first_line": frame.f_code.co_firstlineno})

    sys.addaudithook(audit)
    text = PAYLOAD if input_kind == "arithmetic" else ORDINARY
    result, error = None, None
    sys.setprofile(profile)
    armed = True
    try:
        if audit_control:
            # Compile and exec to test instrumentation with matching flags
            code = compile(EXPRESSION, "<string>", "eval", dont_inherit=True)
            result = eval(code)
        else:
            result = app.entry(text)
    except Exception as exc:
        error = {"type": type(exc).__name__, "module": type(exc).__module__,
                 "message": str(exc)}
    finally:
        armed = False
        sys.setprofile(None)
    return {"status": "COMPLETE", "mode": "audit_control" if audit_control else "runtime",
            "library_version": yaml.__version__, "library_origin": str(origin),
            "libyaml_active": bool(getattr(yaml, "__with_libyaml__", False)),
            "input_kind": input_kind, "input_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "result_type": type(result).__name__, "result_repr": repr(result),
            "is_arithmetic_tuple": type(result) is tuple and result == (42,),
            "is_arithmetic_scalar": type(result) is int and result == 42,
            "ordinary_parse": type(result) is dict and result == {"answer": 42},
            "error": error, "audit_events": events, "python_calls": calls,
            "expected_code_signature": expected_signature}


def static(root):
    output = Path("/tmp/pycg.json")
    # Use -S to isolate from site-packages; pkg_resources is provided in /tools
    command = [sys.executable, "-B", "-S", "-m", "pycg", "--package", str(root),
               str(root / "app.py"), "-o", str(output)]
    environment = dict(os.environ, PYTHONPATH="/tools:" + str(root))
    completed = subprocess.run(command, env=environment, text=True, capture_output=True)
    graph = json.loads(output.read_text()) if completed.returncode == 0 and output.is_file() else None
    return {"status": "COMPLETE" if graph is not None else "ANALYZER_ERROR",
            "mode": "static", "command": command, "returncode": completed.returncode,
            "stdout": completed.stdout, "stderr": completed.stderr, "graph": graph,
            "iteration_policy": "UPSTREAM_FIXED_POINT; no max-iter override"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["static", "runtime", "audit_control", "probe"])
    parser.add_argument("--version", choices=["5.3.1", "5.4.1"], default="5.3.1")
    parser.add_argument("--profile", choices=["direct", "wrapper", "safe", "cooccurrence", "guard"], default="direct")
    parser.add_argument("--input", choices=["arithmetic", "ordinary"], default="ordinary")
    args = parser.parse_args()
    started = time.monotonic()
    root = Path("/analysis") / args.version / args.profile
    environment = {"python": platform.python_version(), "implementation": platform.python_implementation(),
                   "system": platform.system(), "machine": platform.machine()}
    try:
        if args.mode == "probe":
            value = {"status": "COMPLETE", "mode": "probe"}
        elif args.mode == "static":
            value = static(root)
        else:
            value = runtime(root, args.version, args.input, audit_control=args.mode == "audit_control")
    except Exception as exc:
        value = {"status": "EXECUTION_ERROR", "mode": args.mode,
                 "error": {"type": type(exc).__name__, "message": str(exc)}}
    value.update(environment=environment, elapsed_seconds=time.monotonic() - started)
    print(json.dumps(value, sort_keys=True))


if __name__ == "__main__":
    main()
