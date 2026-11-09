"""Credential-free transcripts for the user-authorized Viettel gateway."""
from __future__ import annotations

import getpass
import json
import os
import time
from itertools import count
import httpx

DEFAULT_URL = "https://stream-netmind.viettel.vn/gateway/v1"


class GatewayError(RuntimeError):
    def __init__(self, message, *, retryable=False):
        super().__init__(message)
        self.retryable = retryable


class Gateway:
    def __init__(self, key=None, base_url=DEFAULT_URL, timeout=120, transport=None, streaming=False,
                 unrestricted=False, on_retry=None):
        self._key = key or os.environ.get("NETMIND_API_KEY")
        if not self._key:
            raise GatewayError("NETMIND_API_KEY is required; never put it in a manifest")
        self.base_url = base_url.rstrip("/")
        self.client = httpx.Client(timeout=timeout, follow_redirects=False, transport=transport)
        self.calls = []
        self.requests = []
        self.streaming = streaming
        self.unrestricted = unrestricted
        self.on_retry = on_retry

    def _retry(self, attempt, record, delay=None):
        if self.on_retry:
            self.on_retry({'phase': 'RETRYING_GATEWAY', 'attempt': attempt + 1, 'status': record['status']})
        time.sleep(min(30, max(0, delay if delay is not None else 2 ** min(attempt, 5))))

    def close(self):
        self.client.close()

    def _request(self, method, path, payload=None):
        for attempt in count():
            started = time.perf_counter()
            try:
                response = self.client.request(method, self.base_url + path,
                    headers={"Authorization": "Bearer " + self._key, "Content-Type": "application/json"}, json=payload)
            except httpx.TransportError as exc:
                self.requests.append({"method": method, "path": path, "attempt": attempt + 1,
                                      "status": "TRANSPORT_ERROR", "duration_seconds": time.perf_counter() - started,
                                      "usage": None})
                if attempt == 2 and not self.unrestricted:
                    raise GatewayError(type(exc).__name__) from None
                self._retry(attempt, self.requests[-1])
                continue
            request_record = {"method": method, "path": path, "attempt": attempt + 1,
                              "status": response.status_code, "duration_seconds": time.perf_counter() - started, "usage": None}
            self.requests.append(request_record)
            if response.status_code in (429, 500, 502, 503, 504) and (self.unrestricted or attempt < 2):
                try:
                    delay = min(30, max(0, float(response.headers.get("retry-after", 2 ** min(attempt, 5)))))
                except ValueError:
                    delay = 2 ** min(attempt, 5)
                self._retry(attempt, request_record, delay)
                continue
            if response.status_code >= 400:
                # Provider error bodies and headers may contain credentials; never journal them.
                raise GatewayError(f"Gateway HTTP {response.status_code}")
            try:
                body = response.json()
            except ValueError:
                raise GatewayError("Gateway returned non-JSON", retryable=True) from None
            # Redact even an accidental provider echo before the response leaves the client.
            body = json.loads(json.dumps(body).replace(self._key, "[REDACTED]"))
            request_record["usage"] = body.get("usage")
            self.calls.append({"path": path, "duration_seconds": time.perf_counter() - started,
                               "attempts": attempt + 1, "model": body.get("model"),
                               "usage": body.get("usage"), "system_fingerprint": body.get("system_fingerprint"),
                               "cost": None})
            if payload:
                self.calls[-1]["inference_parameters"] = {k: v for k, v in payload.items() if k not in {"messages", "tools"}}
            return body
        raise GatewayError("Retry budget exhausted")

    def models(self):
        return self._request("GET", "/models")

    @staticmethod
    def _consume_stream(response, *, unrestricted=False):
        message = {"role": "assistant", "content": ""}
        calls, metadata = {}, {}
        finish, characters = None, 0
        started = time.monotonic()
        for line in response.iter_lines():
            if not unrestricted and time.monotonic() - started > 1800:
                raise GatewayError("Gateway stream time limit")
            characters += len(line)
            if not unrestricted and characters > 8_000_000:
                raise GatewayError("Gateway stream size limit")
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                break
            try:
                chunk = json.loads(data)
            except ValueError:
                raise GatewayError("Malformed gateway stream", retryable=True) from None
            if not isinstance(chunk, dict) or chunk.get("error"):
                raise GatewayError("Gateway stream error", retryable=True)
            for key in ("model", "usage", "system_fingerprint"):
                if chunk.get(key) is not None:
                    metadata[key] = chunk[key]
            choices = chunk.get("choices", [])
            if not isinstance(choices, list) or any(not isinstance(c, dict) for c in choices):
                raise GatewayError("Invalid streaming choices", retryable=True)
            for choice in choices:
                if choice.get("index", 0) != 0:
                    continue
                if choice.get("finish_reason") is not None:
                    finish = choice["finish_reason"]
                delta = choice.get("delta") or {}
                if not isinstance(delta, dict):
                    raise GatewayError("Invalid streaming delta", retryable=True)
                content = delta.get("content")
                if content is not None:
                    if not isinstance(content, str):
                        raise GatewayError("Invalid streaming text", retryable=True)
                    message["content"] += content
                items = delta.get("tool_calls", [])
                if not isinstance(items, list) or any(not isinstance(i, dict) for i in items):
                    raise GatewayError("Invalid streaming tool calls", retryable=True)
                for item in items:
                    index = item.get("index")
                    if type(index) is not int or index < 0 or (not unrestricted and index >= 32):
                        raise GatewayError("Invalid streaming tool index", retryable=True)
                    call = calls.setdefault(index, {"id": "", "type": "function", "function": {"name": "", "arguments": ""}})
                    if item.get("id") and isinstance(item["id"], str):
                        call["id"] = item["id"]
                    function = item.get("function", {})
                    if not isinstance(function, dict):
                        raise GatewayError("Invalid streaming function", retryable=True)
                    for key in ("name", "arguments"):
                        fragment = function.get(key)
                        if fragment is not None:
                            if not isinstance(fragment, str):
                                raise GatewayError("Invalid streaming tool fragment", retryable=True)
                            call["function"][key] += fragment
        if finish is None:
            raise GatewayError("Incomplete gateway stream", retryable=True)
        if calls:
            message["tool_calls"] = [calls[i] for i in sorted(calls)]
        return {**metadata, "choices": [{"message": message, "finish_reason": finish}]}

    def _stream_request(self, payload):
        """Opt-in transport; benchmark defaults and frozen campaigns stay unchanged."""
        for attempt in count():
            started = time.perf_counter()
            record = {"method": "POST", "path": "/chat/completions", "attempt": attempt + 1,
                      "status": "PENDING", "usage": None}
            self.requests.append(record)
            try:
                with self.client.stream("POST", self.base_url + "/chat/completions",
                        headers={"Authorization": "Bearer " + self._key, "Content-Type": "application/json"}, json=payload) as response:
                    record.update(status=response.status_code, http_status=response.status_code)
                    if response.status_code in (429, 500, 502, 503, 504) and (self.unrestricted or attempt < 2):
                        try:
                            delay = min(30, max(0, float(response.headers.get("retry-after", 2 ** min(attempt, 5)))))
                        except ValueError:
                            delay = 2 ** min(attempt, 5)
                        self._retry(attempt, record, delay)
                        continue
                    if response.status_code >= 400:
                        raise GatewayError(f"Gateway HTTP {response.status_code}")
                    if "text/event-stream" in response.headers.get("content-type", ""):
                        body = self._consume_stream(response, unrestricted=self.unrestricted)
                        record["response_transport"] = "SSE"
                    else:
                        response.read()
                        try:
                            body = response.json()
                        except ValueError:
                            raise GatewayError("Gateway returned non-JSON", retryable=True) from None
                        record["response_transport"] = "JSON_FALLBACK"
            except httpx.TransportError as exc:
                record["status"] = "TRANSPORT_ERROR"
                if attempt == 2 and not self.unrestricted:
                    raise GatewayError(type(exc).__name__) from None
                self._retry(attempt, record)
                continue
            finally:
                record["duration_seconds"] = time.perf_counter() - started
            body = json.loads(json.dumps(body).replace(self._key, "[REDACTED]"))
            record["usage"] = body.get("usage")
            self.calls.append({"path": "/chat/completions", "duration_seconds": record["duration_seconds"],
                "attempts": attempt + 1, "model": body.get("model"), "usage": body.get("usage"),
                "system_fingerprint": body.get("system_fingerprint"), "cost": None,
                "response_transport": record["response_transport"],
                "inference_parameters": {k: v for k, v in payload.items() if k not in {"messages", "tools"}}})
            return body
        raise GatewayError("Retry budget exhausted")

    def chat(self, model, messages, max_tokens=4096, tools=None, seed=None):
        payload = {"model": model, "messages": messages, "temperature": 0, "stream": False}
        if max_tokens is not None:
            payload['max_tokens'] = max_tokens
        if tools:
            payload.update(tools=tools, tool_choice="auto")
        if seed is not None:
            payload["seed"] = seed
        if "qwen" in model.lower():
            payload["chat_template_kwargs"] = {"enable_thinking": False}
        if self.streaming:
            payload.update(stream=True, stream_options={"include_usage": True})
        response = self._stream_request(payload) if self.streaming else self._request("POST", "/chat/completions", payload)
        try:
            choice = response["choices"][0]
            msg = choice["message"]
        except (KeyError, IndexError, TypeError):
            raise GatewayError("Invalid chat response shape", retryable=True) from None
        if choice.get("finish_reason") == "length":
            raise GatewayError("Truncated model response", retryable=True)
        return msg, self.calls[-1]

    def preflight(self, models=None):
        listing = self.models()
        ids = [r["id"] for r in listing.get("data", [])]
        selected = models or [m for m in ids if any(t in m.lower() for t in ("qwen", "claude", "sea-lion"))]
        results = []
        tool = {"type": "function", "function": {"name": "inspect", "description": "Inspect an SBOM",
                "parameters": {"type": "object", "properties": {}, "additionalProperties": False}}}
        for model in selected:
            if model not in ids:
                results.append({"model": model, "status": "NOT_LISTED"})
                continue
            row = {"model": model}
            try:
                msg, stats = self.chat(model, [{"role": "user", "content": 'Return exactly {"ok":true} as JSON.'}], max_tokens=512)
                content = msg.get("content", "")
                row.update(status="CHAT_AVAILABLE", json_response=content, chat_stats=stats)
                try:
                    row["json_valid"] = json.loads(content) == {"ok": True}
                except (ValueError, TypeError):
                    row["json_valid"] = False
                try:
                    tmsg, tstats = self.chat(model, [{"role": "user", "content": "Use the inspect tool now."}],
                                              max_tokens=512, tools=[tool])
                    row.update(native_tools=bool(tmsg.get("tool_calls")), tool_stats=tstats)
                except GatewayError as exc:
                    row.update(native_tools=False, tool_probe_error=str(exc))
                row["agent_protocol"] = "VALIDATED_JSON_ACTIONS" if row["json_valid"] else "UNUSABLE_JSON"
            except GatewayError as exc:
                row.update(status="FAILED", error=str(exc))
            results.append(row)
        return {"schema_version": "gateway-preflight-v1", "base_url": self.base_url,
                "auth_scheme": "Bearer", "models": ids, "probes": results,
                "chat_transport": "SSE_OPT_IN" if self.streaming else "NON_STREAMING",
                "model_cost": None, "provider_revision": "UNKNOWN_UNLESS_FINGERPRINT_RETURNED"}


def read_key(interactive=False):
    return getpass.getpass("Gateway key: ") if interactive else os.environ.get("NETMIND_API_KEY")
