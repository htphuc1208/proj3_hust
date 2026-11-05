"""Web UI server for SBOM Security Recovery PoC."""
import json
import os
import subprocess
import sys
import threading
import time
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from ui import budget_api
CAPTURES_ROOT = ROOT / "research/.work/m25-cohort-captures-v2"
RUNS_ROOT = ROOT / "runs"
VENV_PYTHON = ROOT / ".venv/bin/python"

# In-memory execution job tracking
JOBS = {}
JOBS_LOCK = threading.Lock()


def get_available_projects():
    projects = []
    if not CAPTURES_ROOT.exists():
        return projects
    for p in sorted(CAPTURES_ROOT.iterdir()):
        if not p.is_dir():
            continue
        ctx = p / "context.json"
        tgt = p / "runtime/target"
        if ctx.exists() and tgt.exists():
            scanners = []
            runtime = p / "runtime"
            for f in sorted(runtime.glob("*.spdx.json")):
                scanners.append(f.name)
            for f in sorted(runtime.glob("*.cdx.json")):
                scanners.append(f.name)
            projects.append({
                "name": p.name,
                "context_path": str(ctx.relative_to(ROOT)),
                "target_path": str(tgt.relative_to(ROOT)),
                "scanners": scanners
            })
    return projects


def get_runs_list():
    runs = []
    if not RUNS_ROOT.exists():
        return runs
    for p in sorted(RUNS_ROOT.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
        if not p.is_dir():
            continue
        res_file = p / "result.json"
        if res_file.exists():
            try:
                data = json.loads(res_file.read_text(encoding="utf-8"))
                policy = data.get("policy", "deterministic")
                created_at = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(p.stat().st_mtime))
                runs.append({
                    "id": p.name,
                    "path": str(p.relative_to(ROOT)),
                    "policy": policy,
                    "model": data.get("model", "N/A"),
                    "status": data.get("status", "UNKNOWN"),
                    "created_at": created_at
                })
            except Exception:
                pass
    return runs[:50]


def extract_graph_data(input_doc, recovered_doc, result):
    if not input_doc or not recovered_doc:
        return None
    try:
        from sbom_recovery.formats import NativeDocument
        doc_in = NativeDocument(input_doc)
        doc_out = NativeDocument(recovered_doc)

        in_pkgs = doc_in.packages()
        out_pkgs = doc_out.packages()
        in_edges_raw = doc_in.edges()
        out_edges_raw = doc_out.edges()

        # Proposal changes from result
        accepted_list = (result.get("verified", {}).get("accepted", [])
                         if isinstance(result, dict) else [])
        repaired_subjects = set()
        added_subjects = set()
        recovered_delta = []

        for item in accepted_list:
            p = item.get("proposal", {})
            op = p.get("operation")
            sub = p.get("subject")
            field = p.get("field")
            val = p.get("value")
            bef = p.get("before")

            sub_pkg = out_pkgs.get(sub) or in_pkgs.get(sub) or {}
            sub_name = sub_pkg.get("name") or sub

            if op == "set_field":
                repaired_subjects.add(sub)
                recovered_delta.append({
                    "type": "METADATA_REPAIRED",
                    "operation": op,
                    "subject_id": sub,
                    "subject_name": sub_name,
                    "field": field,
                    "before": bef,
                    "after": val,
                    "authority": item.get("status", "VERIFIED_TARGET")
                })
            elif op == "add_dependency":
                val_pkg = out_pkgs.get(val) or in_pkgs.get(val) or {}
                val_name = val_pkg.get("name") or val
                recovered_delta.append({
                    "type": "DEPENDENCY_ADDED",
                    "operation": op,
                    "source_id": sub,
                    "source_name": sub_name,
                    "target_id": val,
                    "target_name": val_name,
                    "authority": item.get("status", "VERIFIED_TARGET")
                })
            elif op == "add_component":
                added_subjects.add(sub)
                recovered_delta.append({
                    "type": "COMPONENT_ADDED",
                    "operation": op,
                    "subject_id": sub,
                    "subject_name": sub_name,
                    "value": val,
                    "authority": item.get("status", "VERIFIED_TARGET")
                })

        def format_nodes(pkgs, is_out=False):
            nodes = []
            for ref, p in pkgs.items():
                name = p.get("name") or ref
                version = p.get("versionInfo") or p.get("version") or ""
                nodes.append({
                    "id": ref,
                    "name": name,
                    "version": version,
                    "is_new": (ref in added_subjects) if is_out else False,
                    "is_repaired": (ref in repaired_subjects) if is_out else False
                })
            return nodes

        def format_edges(edges_set, pkgs, is_out=False):
            edges = []
            for src, dst in edges_set:
                src_name = pkgs.get(src, {}).get("name") or src
                dst_name = pkgs.get(dst, {}).get("name") or dst
                is_new = ((src, dst) not in in_edges_raw) if is_out else False
                edges.append({
                    "source": src,
                    "target": dst,
                    "source_name": src_name,
                    "target_name": dst_name,
                    "is_new": is_new
                })
            return edges

        return {
            "initial": {
                "nodes": format_nodes(in_pkgs, False),
                "edges": format_edges(in_edges_raw, in_pkgs, False)
            },
            "recovered": {
                "nodes": format_nodes(out_pkgs, True),
                "edges": format_edges(out_edges_raw, out_pkgs, True)
            },
            "delta": {
                "changes_list": recovered_delta,
                "added_edges_count": len(out_edges_raw - in_edges_raw),
                "repaired_fields_count": len([d for d in recovered_delta if d["type"] == "METADATA_REPAIRED"]),
                "added_components_count": len(added_subjects)
            }
        }
    except Exception as e:
        return {"error": f"Failed to extract graph data: {str(e)}"}


def get_run_details(run_path_str):
    run_dir = (ROOT / run_path_str).resolve()
    if not run_dir.is_relative_to((ROOT / "runs").resolve()):
        return None
    if not run_dir.exists() or not run_dir.is_dir():
        return None

    def read_json_if_exists(filename):
        f = run_dir / filename
        if f.exists():
            try:
                return json.loads(f.read_text(encoding="utf-8"))
            except Exception as e:
                return {"error": f"Failed to parse {filename}: {str(e)}"}
        return None

    result = read_json_if_exists("result.json")
    candidates = read_json_if_exists("candidates.json")
    conversion_audit = read_json_if_exists("conversion_audit.json")
    cyclonedx_val = read_json_if_exists("cyclonedx_validation.json")
    context = read_json_if_exists("context.json")
    input_doc = read_json_if_exists("input.json")
    recovered_cdx = read_json_if_exists("recovered.cdx.json")
    recovered_spdx = read_json_if_exists("recovered.spdx.json")

    # Turns if any
    turns = []
    for turn_file in sorted(run_dir.glob("turn-*.json")):
        try:
            turns.append(json.loads(turn_file.read_text(encoding="utf-8")))
        except Exception:
            pass

    # Extract Graph and Delta
    recovered_doc = recovered_spdx if recovered_spdx else recovered_cdx
    graph_data = extract_graph_data(input_doc, recovered_doc, result)

    return {
        "run_id": run_dir.name,
        "run_path": str(run_dir.relative_to(ROOT)),
        "result": result,
        "candidates": candidates,
        "conversion_audit": conversion_audit,
        "cyclonedx_validation": cyclonedx_val,
        "context": context,
        "input": input_doc,
        "recovered_cdx": recovered_cdx,
        "recovered_spdx": recovered_spdx,
        "turns": turns,
        "graph_data": graph_data
    }


def execute_job(job_id, params):
    policy = params.get("policy", "deterministic")
    input_file = ROOT / params.get("input_file", "")
    context_file = ROOT / params.get("context_file", "")
    target_path = ROOT / params.get("target_path", "")
    model = params.get("model", "Qwen/Qwen3.6-35B-A3B-FP8")
    streaming = bool(params.get("streaming", True))
    api_key = params.get("api_key") or os.environ.get("NETMIND_API_KEY", "")

    timestamp = time.strftime("%Y%m%d-%H%M%S")
    proj_name = params.get("project_name", "custom")
    out_dir_name = f"runs/poc-{policy}-{proj_name}-{timestamp}"
    out_path = ROOT / out_dir_name

    cmd = [
        str(VENV_PYTHON), "-B", "-m", "sbom_recovery", "recover",
        "--input", str(input_file),
        "--context", str(context_file),
        "--target", str(target_path),
        "--policy", policy,
        "--out", str(out_path)
    ]

    if policy in ("single_agent", "multi_agent"):
        cmd.extend(["--model", model])
        if streaming:
            cmd.append("--stream")

    env = os.environ.copy()
    if api_key:
        env["NETMIND_API_KEY"] = api_key

    with JOBS_LOCK:
        JOBS[job_id]["cmd"] = " ".join(cmd)
        JOBS[job_id]["out_dir"] = out_dir_name
        JOBS[job_id]["status"] = "RUNNING"
        JOBS[job_id]["logs"].append(f"[*] Starting SBOM Recovery with policy: {policy}\n")
        JOBS[job_id]["logs"].append(f"[*] Output directory: {out_dir_name}\n")
        JOBS[job_id]["logs"].append(f"[*] Executing command:\n    {' '.join(cmd)}\n\n")

    started_at = time.time()
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(ROOT),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        for line in proc.stdout:
            with JOBS_LOCK:
                JOBS[job_id]["logs"].append(line)

        proc.wait()
        duration = time.time() - started_at

        with JOBS_LOCK:
            if proc.returncode == 0:
                JOBS[job_id]["status"] = "SUCCESS"
                JOBS[job_id]["duration"] = duration
                JOBS[job_id]["logs"].append(f"\n[+] Recovery completed successfully in {duration:.2f}s!\n")
            else:
                JOBS[job_id]["status"] = "FAILED"
                JOBS[job_id]["duration"] = duration
                JOBS[job_id]["logs"].append(f"\n[-] Process failed with return code {proc.returncode} in {duration:.2f}s.\n")

    except Exception as exc:
        with JOBS_LOCK:
            JOBS[job_id]["status"] = "ERROR"
            JOBS[job_id]["logs"].append(f"\n[!] Exception during execution: {str(exc)}\n")


class RecoveryUIHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if not self.local_host():
            self.send_json({"error":"Local interface only"},403)
            return
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path in ("/", "/agent", "/index.html"):
            self.serve_static_file("agent.html", "text/html")
        elif path == "/legacy":
            self.serve_static_file("index.html", "text/html")
        elif path in ("/agent.css", "/agent.js"):
            self.serve_static_file(path[1:], "text/css" if path.endswith("css") else "application/javascript")
        elif path.startswith("/api/agent/"):
            try:
                if path == "/api/agent/settings":
                    value={"gateway_configured":bool(os.environ.get("NETMIND_API_KEY")),"models":[budget_api.MODEL]}
                elif path == "/api/agent/projects": value=budget_api.projects()
                elif path == "/api/agent/reachability":
                    from ui.reachability_api import latest
                    value=latest()
                elif path == "/api/agent/runs": value=budget_api.list_runs()
                elif path == "/api/agent/details": value=budget_api.details(query.get("run",[""])[0])
                elif path == "/api/agent/job": value=budget_api.job_status(query.get("id",[""])[0])
                elif path == "/api/agent/evidence": value=budget_api.evidence(query.get("run",[""])[0],query.get("source",[""])[0])
                else: raise ValueError("Unknown endpoint")
                self.send_json(value)
            except (ValueError,KeyError,OSError):
                self.send_json({"error":"Không tìm thấy dữ liệu hợp lệ cho yêu cầu này."},400)
        elif path == "/styles.css":
            self.serve_static_file("styles.css", "text/css")
        elif path == "/app.js":
            self.serve_static_file("app.js", "application/javascript")
        elif path == "/api/projects":
            self.send_json(get_available_projects())
        elif path == "/api/runs":
            self.send_json(get_runs_list())
        elif path == "/api/run-details":
            run_path = query.get("run", [""])[0]
            details = get_run_details(run_path)
            if details:
                self.send_json(details)
            else:
                self.send_error(404, "Run not found")
        elif path == "/api/job-status":
            job_id = query.get("job_id", [""])[0]
            with JOBS_LOCK:
                job = JOBS.get(job_id)
                if not job:
                    self.send_error(404, "Job not found")
                    return
                self.send_json({
                    "id": job_id,
                    "status": job["status"],
                    "out_dir": job["out_dir"],
                    "logs": "".join(job["logs"]),
                    "duration": job.get("duration")
                })
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        if not self.local_host():
            self.send_json({"error":"Local interface only"},403)
            return
        parsed = urlparse(self.path)
        origin=self.headers.get("Origin")
        if origin and origin not in {"http://"+self.headers.get("Host",""),"https://"+self.headers.get("Host","")}:
            self.send_json({"error":"Cross-origin requests denied"},403)
            return
        if parsed.path == "/api/agent/run":
            try:
                length=int(self.headers.get("Content-Length",0))
                if not 0<length<=1600000:raise ValueError("Payload size invalid")
                params=json.loads(self.rfile.read(length))
                self.send_json(budget_api.start(params),202)
            except (ValueError,TypeError,KeyError):
                self.send_json({"error":"Kiểm tra target, scanner, phương pháp, ngân sách và định dạng JSON."},400)
            return
        if parsed.path == "/api/run":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            try:
                params = json.loads(body.decode("utf-8"))
            except Exception:
                self.send_error(400, "Invalid JSON payload")
                return

            job_id = uuid.uuid4().hex
            with JOBS_LOCK:
                JOBS[job_id] = {
                    "id": job_id,
                    "status": "QUEUED",
                    "logs": [],
                    "out_dir": "",
                    "duration": None
                }

            thread = threading.Thread(target=execute_job, args=(job_id, params), daemon=True)
            thread.start()

            self.send_json({"job_id": job_id, "status": "QUEUED"})
        else:
            self.send_error(404, "Not Found")

    def serve_static_file(self, filename, content_type):
        filepath = Path(__file__).parent / filename
        if not filepath.exists():
            self.send_error(404, f"File {filename} not found")
            return
        content = filepath.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def local_host(self):
        try:
            return urlparse("http://"+self.headers.get("Host","")).hostname in {"localhost","127.0.0.1","::1"}
        except ValueError:
            return False

    def send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    from dotenv import load_dotenv
    load_dotenv(ROOT/".env",override=False)
    port = 8088
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass

    server = HTTPServer(("127.0.0.1", port), RecoveryUIHandler)
    print(f"SBOM Recovery UI running at http://localhost:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()


if __name__ == "__main__":
    main()
