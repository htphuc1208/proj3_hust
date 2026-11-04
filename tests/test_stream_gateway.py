"""Streaming protocol and accounting tests; synthetic frames are not model results."""
import json
import unittest
from unittest.mock import patch
import httpx

from sbom_recovery.llm import Gateway, GatewayError


def frames(*data):
    return ("\n\n".join("data: " + (json.dumps(d) if isinstance(d, dict) else d) for d in data) + "\n\n").encode()


def completed():
    return frames({"model":"model","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[
        {"index":0,"id":"call-1","function":{"name":"inspect","arguments":"{"}}]}}]},
        {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"}"}}]}}]},
        {"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]},
        {"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}},"[DONE]")


class StreamingGatewayTests(unittest.TestCase):
    def make(self, handler):
        return Gateway("test-secret",streaming=True,transport=httpx.MockTransport(handler))

    def test_reassembles_native_tool_arguments_and_usage(self):
        def handler(request):
            body=json.loads(request.content)
            self.assertTrue(body["stream"])
            self.assertTrue(body["stream_options"]["include_usage"])
            self.assertEqual(request.headers["Authorization"],"Bearer test-secret")
            return httpx.Response(200,headers={"content-type":"text/event-stream"},content=completed())
        g=self.make(handler)
        try:
            message,stats=g.chat("model",[])
            self.assertEqual(message["tool_calls"][0]["function"],{"name":"inspect","arguments":"{}"})
            self.assertEqual(stats["usage"]["total_tokens"],15)
            self.assertEqual(stats["response_transport"],"SSE")
        finally:g.close()

    def test_stream_retry_preserves_unknown_usage_for_interrupted_attempt(self):
        class Broken(httpx.SyncByteStream):
            def __iter__(self):
                yield frames({"choices":[{"delta":{"content":"partial"}}]})
                raise httpx.ReadTimeout("do not journal test-secret")
        count=0
        def handler(request):
            nonlocal count
            count+=1
            return httpx.Response(200,headers={"content-type":"text/event-stream"},
                stream=Broken()) if count==1 else httpx.Response(200,headers={"content-type":"text/event-stream"},content=completed())
        g=self.make(handler)
        try:
            with patch("sbom_recovery.llm.time.sleep"):
                _,stats=g.chat("model",[])
            self.assertEqual(len(g.requests),2)
            self.assertIsNone(g.requests[0]["usage"])
            self.assertEqual(stats["attempts"],2)
            self.assertNotIn("test-secret",json.dumps(g.calls)+json.dumps(g.requests))
        finally:g.close()

    def test_malformed_incomplete_and_error_frames_fail_closed(self):
        for data in (frames("bad-json"),frames({"choices":[{"delta":{"content":"partial"}}]},"[DONE]"),
                     frames({"error":{"message":"test-secret"}})):
            with self.subTest(data_length=len(data)):
                g=self.make(lambda request:httpx.Response(200,headers={"content-type":"text/event-stream"},content=data))
                try:
                    with self.assertRaises(GatewayError) as error:g.chat("model",[])
                    self.assertNotIn("test-secret",str(error.exception))
                    self.assertEqual(g.calls,[])
                finally:g.close()

    def test_http_errors_and_provider_echo_never_expose_credentials(self):
        g=self.make(lambda request:httpx.Response(400,json={"error":"test-secret"}))
        try:
            with self.assertRaisesRegex(GatewayError,"HTTP 400"):g.chat("model",[])
            self.assertNotIn("test-secret",json.dumps(g.requests))
        finally:g.close()
        body=frames({"choices":[{"delta":{"content":"test-secret"},"finish_reason":"stop"}]},"[DONE]")
        g=self.make(lambda request:httpx.Response(200,headers={"content-type":"text/event-stream"},content=body))
        try:
            message,_=g.chat("model",[])
            self.assertEqual(message["content"],"[REDACTED]")
        finally:g.close()

    def test_json_fallback_and_length_limit_are_explicit(self):
        g=self.make(lambda request:httpx.Response(200,json={"choices":[{"message":{"role":"assistant","content":"{}"},"finish_reason":"stop"}]}))
        try:
            _,stats=g.chat("model",[])
            self.assertEqual(stats["response_transport"],"JSON_FALLBACK")
        finally:g.close()
        data=frames({"choices":[{"delta":{"content":"{"},"finish_reason":"length"}],"usage":{"total_tokens":1}},"[DONE]")
        g=self.make(lambda request:httpx.Response(200,headers={"content-type":"text/event-stream"},content=data))
        try:
            with self.assertRaisesRegex(GatewayError,"Truncated"):g.chat("model",[])
            self.assertEqual(g.calls[0]["usage"]["total_tokens"],1)
        finally:g.close()

    def test_unrestricted_transport_retries_past_three_and_omits_output_cap(self):
        attempts=[]
        def handler(request):
            body=json.loads(request.content);self.assertNotIn('max_tokens',body)
            attempts.append(body)
            if len(attempts)<=4:return httpx.Response(503)
            return httpx.Response(200,headers={'content-type':'text/event-stream'},content=completed())
        gateway=Gateway('test-secret',streaming=True,unrestricted=True,transport=httpx.MockTransport(handler))
        try:
            with patch('sbom_recovery.llm.time.sleep'):
                message,stats=gateway.chat('model',[],max_tokens=None)
            self.assertEqual(stats['attempts'],5)
            self.assertEqual(len(gateway.requests),5)
            self.assertTrue(message['tool_calls'])
        finally:gateway.close()


if __name__=="__main__":unittest.main()
