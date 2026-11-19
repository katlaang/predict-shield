import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

from predict_shield.language_model import (HostedChatModel, ModelUnavailable, OllamaModel, RecordedModel,
                                           RecordingModel, open_model, parse_json_object)
from scripted_model import ScriptedModel


class ParseTests(unittest.TestCase):
    def test_accepts_plain_fenced_and_wrapped_objects(self):
        for text in ('{"a": 1}', '```json\n{"a": 1}\n```', 'Here you go: {"a": 1} done'):
            self.assertEqual(parse_json_object(text), {"a": 1})

    def test_refuses_anything_that_is_not_one_object(self):
        for text in ("", "no json here", "[1, 2]", '{"a": ', None):
            with self.assertRaises(ValueError):
                parse_json_object(text)


class RecordingTests(unittest.TestCase):
    def test_replay_returns_recorded_replies_and_refuses_new_requests(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "exchanges.json"
            live = RecordingModel(ScriptedModel([("hello", '{"ok": true}')]), path)
            self.assertEqual(live.complete("system", "hello there"), '{"ok": true}')
            replay = RecordedModel(path)
            self.assertEqual(replay.name, "recorded:scripted")
            self.assertEqual(replay.complete("system", "hello there"), '{"ok": true}')
            with self.assertRaises(ModelUnavailable):
                replay.complete("system", "a different request")
            with self.assertRaises(ModelUnavailable):
                replay.complete("a different system prompt", "hello there")

    def test_model_spec(self):
        self.assertEqual(open_model("ollama:some-model").name, "ollama:some-model")
        for spec in ("", "ollama:", "cloud:some-model", "some-model"):
            with self.assertRaises(ValueError):
                open_model(spec)

    def test_recording_never_stores_a_hosted_api_key(self):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.dict(os.environ, {"FEATHERLESS_API_KEY": "sk-do-not-leak-this"}):
            model = open_model("featherless:some-model",
                               record_to=Path(directory) / "exchanges.json")
            inner = model.inner
            inner.complete = lambda system, prompt: '{"affected": []}'   # stub the network call
            model.complete("sys", "prompt")
            saved = (Path(directory) / "exchanges.json").read_text(encoding="utf-8")
            self.assertNotIn("sk-do-not-leak-this", saved)
            self.assertNotIn("Authorization", saved)


class OllamaTests(unittest.TestCase):
    def test_request_shape_and_reply_parsing_against_a_local_stub(self):
        seen = {}

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                seen["path"] = self.path
                seen["body"] = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                body = json.dumps({"message": {"role": "assistant", "content": '{"affected": []}'}}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.handle_request, daemon=True).start()
        try:
            schema = {"type": "object", "properties": {"affected": {"type": "array"}}}
            model = OllamaModel("some-model", host=f"http://127.0.0.1:{server.server_port}", timeout=5,
                                format_schema=schema)
            self.assertEqual(model.complete("sys", "user"), '{"affected": []}')
        finally:
            server.server_close()
        self.assertEqual(seen["path"], "/api/chat")
        self.assertEqual(seen["body"]["model"], "some-model")
        self.assertIs(seen["body"]["stream"], False)
        self.assertEqual(seen["body"]["options"]["temperature"], 0)
        self.assertEqual(seen["body"]["format"], schema)
        self.assertEqual([m["role"] for m in seen["body"]["messages"]], ["system", "user"])

    def test_unreachable_server_is_reported_as_unavailable(self):
        with self.assertRaises(ModelUnavailable):
            OllamaModel("some-model", host="http://127.0.0.1:9", timeout=2).complete("s", "p")


class HostedChatModelTests(unittest.TestCase):
    def test_unknown_provider_is_rejected(self):
        with mock.patch.dict(os.environ, {"TOGETHER_API_KEY": "key"}):
            with self.assertRaises(ValueError):
                HostedChatModel("openai", "some-model")

    def test_missing_api_key_is_reported_as_unavailable_not_a_crash(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ModelUnavailable):
                HostedChatModel("together", "some-model")

    def test_request_shape_auth_header_and_reply_parsing_against_a_local_stub(self):
        seen = {}

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                seen["path"] = self.path
                seen["headers"] = dict(self.headers)
                seen["body"] = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                body = json.dumps({"choices": [{"message": {"content": '{"action": null}'}}]}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.handle_request, daemon=True).start()
        try:
            with mock.patch.dict(os.environ, {"TOGETHER_API_KEY": "sk-test-key"}):
                model = HostedChatModel("together", "org/some-model",
                                        base_url=f"http://127.0.0.1:{server.server_port}/v1", timeout=5)
                self.assertEqual(model.complete("sys", "user"), '{"action": null}')
        finally:
            server.server_close()
        self.assertEqual(seen["path"], "/v1/chat/completions")
        self.assertEqual(seen["headers"]["Authorization"], "Bearer sk-test-key")
        self.assertEqual(seen["body"]["model"], "org/some-model")
        self.assertEqual(seen["body"]["temperature"], 0)
        self.assertEqual([m["role"] for m in seen["body"]["messages"]], ["system", "user"])

    def test_unreachable_server_is_reported_as_unavailable(self):
        with mock.patch.dict(os.environ, {"TOGETHER_API_KEY": "key"}):
            model = HostedChatModel("together", "some-model", base_url="http://127.0.0.1:9", timeout=2)
            with self.assertRaises(ModelUnavailable):
                model.complete("s", "p")

    def test_hosted_model_name_never_includes_the_key(self):
        with mock.patch.dict(os.environ, {"FEATHERLESS_API_KEY": "sk-secret"}):
            self.assertEqual(HostedChatModel("featherless", "some-model").name, "featherless:some-model")

    def test_open_model_dispatches_to_hosted_providers(self):
        with mock.patch.dict(os.environ, {"FEATHERLESS_API_KEY": "key"}):
            self.assertEqual(open_model("featherless:fdtn-ai/Foundation-Sec-8B-Reasoning").name,
                             "featherless:fdtn-ai/Foundation-Sec-8B-Reasoning")


if __name__ == "__main__":
    unittest.main()
