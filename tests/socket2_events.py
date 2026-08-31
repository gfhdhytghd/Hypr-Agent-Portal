#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
from pathlib import Path
import socket
import stat
import struct
import sys
import tempfile
import threading
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("hypr_socket2", ROOT / "mcp" / "hypr_socket2.py")
assert SPEC is not None and SPEC.loader is not None
hypr_socket2 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = hypr_socket2
SPEC.loader.exec_module(hypr_socket2)


class FakeSocket2:
    """A minimal Unix stream server with one script per client connection."""

    def __init__(self, path: Path, sessions: list[list[tuple[float, bytes]]]) -> None:
        self.path = path
        self.sessions = sessions
        self.ready = threading.Event()
        self.stop = threading.Event()
        self.error: BaseException | None = None
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> FakeSocket2:
        self.thread.start()
        if not self.ready.wait(2):
            raise RuntimeError("fake socket2 did not start")
        if self.error:
            raise self.error
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.stop.set()
        # Wake accept() without waiting for the client timeout.
        wake = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            wake.settimeout(0.1)
            wake.connect(str(self.path))
        except OSError:
            pass
        finally:
            wake.close()
        self.thread.join(timeout=2)
        if exc is None and self.error:
            raise self.error

    def _serve(self) -> None:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(self.path))
            listener.listen()
            listener.settimeout(0.1)
            self.ready.set()
            for script in self.sessions:
                while not self.stop.is_set():
                    try:
                        connection, _ = listener.accept()
                        break
                    except socket.timeout:
                        continue
                else:
                    return
                with connection:
                    for delay, chunk in script:
                        if self.stop.wait(delay):
                            return
                        try:
                            connection.sendall(chunk)
                        except (BrokenPipeError, ConnectionResetError):
                            break
        except BaseException as exc:
            self.error = exc
            self.ready.set()
        finally:
            listener.close()
            try:
                self.path.unlink()
            except FileNotFoundError:
                pass


class Socket2EventTests(unittest.TestCase):
    def test_resolves_normal_and_short_injected_socket_paths(self) -> None:
        normal = hypr_socket2.resolve_socket2_path(
            environ={
                "XDG_RUNTIME_DIR": "/run/user/1000",
                "HYPRLAND_INSTANCE_SIGNATURE": "abcd_1234",
            }
        )
        self.assertEqual(normal, Path("/run/user/1000/hypr/abcd_1234/.socket2.sock"))

        short = hypr_socket2.resolve_socket2_path(
            environ={hypr_socket2.SOCKET_PATH_ENV: "/tmp/hp-s2/test.sock"}
        )
        self.assertEqual(short, Path("/tmp/hp-s2/test.sock"))
        with self.assertRaises(hypr_socket2.Socket2ConfigurationError):
            hypr_socket2.resolve_socket2_path(environ={})
        with self.assertRaises(hypr_socket2.Socket2ConfigurationError):
            hypr_socket2.resolve_socket2_path(
                environ={
                    "XDG_RUNTIME_DIR": "/run/user/1000",
                    "HYPRLAND_INSTANCE_SIGNATURE": "../escape",
                }
            )

    def test_parser_preserves_commas_in_openwindow_title(self) -> None:
        event = hypr_socket2.parse_event_line(
            b"openwindow>>abc123,1,org.example.App,Save, As\n", received_at=7.0
        )
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.name, "openwindow")
        self.assertEqual(
            hypr_socket2.event_details(event),
            {
                "address": "abc123",
                "workspace": "1",
                "class": "org.example.App",
                "title": "Save, As",
            },
        )
        self.assertEqual(event.received_at, 7.0)
        self.assertIsNone(hypr_socket2.parse_event_line("not-an-event"))
        dense_title = "title" + "," * 10_000 + "end"
        dense = hypr_socket2.parse_event_line(f"openwindow>>abc,1,App,{dense_title}")
        assert dense is not None
        self.assertLessEqual(len(dense.fields), hypr_socket2._MAX_EVENT_FIELDS)
        self.assertEqual(hypr_socket2.event_details(dense)["title"], dense_title)

    def test_workspace_and_move_events_have_named_details(self) -> None:
        workspace = hypr_socket2.parse_event_line("workspacev2>>-99,special:tools")
        moved = hypr_socket2.parse_event_line("movewindowv2>>abc,-99,special:tools")
        closed = hypr_socket2.parse_event_line("closewindow>>abc")
        assert workspace is not None and moved is not None and closed is not None
        self.assertEqual(
            hypr_socket2.event_details(workspace),
            {"workspaceId": "-99", "workspace": "special:tools"},
        )
        self.assertEqual(
            hypr_socket2.event_details(moved),
            {"address": "abc", "workspaceId": "-99", "workspace": "special:tools"},
        )
        self.assertEqual(hypr_socket2.event_details(closed), {"address": "abc"})

    def test_wait_for_window_filters_unrelated_events(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "s.sock"
            script = [[
                (0.01, b"workspace>>2\nopenwindow>>111,2,Other,Wrong title\n"),
                (0.01, b"openwindow>>aBc,2,Firefox,Requested page\n"),
            ]]
            with FakeSocket2(path, script):
                result = hypr_socket2.wait_for_window(
                    {"address": "0xABC", "class_name": "fire", "title": "requested"},
                    socket_path=path,
                    timeout=1,
                )
        self.assertEqual(result["status"], "matched")
        self.assertEqual(result["method"], "socket2")
        self.assertTrue(result["eventDriven"])
        self.assertNotIn("socketPath", result)
        self.assertEqual(result["socket"]["source"], "explicit")
        self.assertTrue(result["socket"]["pathDigest"].startswith("sha256:"))
        self.assertNotIn(str(path), repr(result))
        self.assertEqual(result["details"]["address"], "aBc")
        self.assertFalse(result["pollFallback"]["used"])

    def test_wait_for_close_reconnects_after_clean_disconnect(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "s.sock"
            sessions = [
                [(0.01, b"closewindow>>wrong\n")],
                [(0.01, b"workspace>>4\nclosewindow>>BEEF\n")],
            ]
            with FakeSocket2(path, sessions):
                result = hypr_socket2.wait_for_close(
                    "0xbeef", socket_path=path, timeout=1, reconnect_delay=0.01
                )
        self.assertEqual(result["status"], "matched")
        self.assertGreaterEqual(result["reconnects"], 1)
        self.assertEqual(result["event"]["name"], "closewindow")

    def test_timeout_while_connected_is_reported_without_implicit_polling(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "s.sock"
            with FakeSocket2(path, [[(0.5, b"workspace>>late\n")]]):
                started = time.monotonic()
                result = hypr_socket2.wait_for_event(
                    "openwindow", socket_path=path, timeout=0.08, reconnect_delay=0.01
                )
                elapsed = time.monotonic() - started
        self.assertEqual(result["status"], "timeout")
        self.assertTrue(result["connected"])
        self.assertLess(elapsed, 0.4)
        self.assertEqual(
            result["pollFallback"],
            {"used": False, "available": False, "reason": "no matching event before timeout"},
        )

    def test_unavailable_socket_uses_only_explicit_poll_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.sock"
            calls: list[str] = []

            def fallback() -> dict[str, str]:
                calls.append("called")
                return {"address": "abc"}

            result = hypr_socket2.wait_for_window(
                {"class": "Example"},
                socket_path=missing,
                timeout=0.04,
                reconnect_delay=0.005,
                poll_fallback=fallback,
            )
        self.assertEqual(calls, ["called"])
        self.assertEqual(result["status"], "matched")
        self.assertEqual(result["method"], "poll")
        self.assertFalse(result["eventDriven"])
        self.assertTrue(result["pollFallback"]["used"])
        self.assertTrue(result["pollFallback"]["matched"])
        self.assertGreater(result["reconnects"], 0)
        self.assertNotIn(str(missing), repr(result))

    def test_poll_fallback_redacts_path_values_and_exception_filenames(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.sock"
            private = "/home/alice/private/fallback.json"
            result = hypr_socket2.wait_for_event(
                "openwindow",
                socket_path=missing,
                timeout=0.02,
                reconnect_delay=0.001,
                poll_fallback=lambda: {"path": private, "nested": [private], "address": "abc"},
            )
            self.assertNotIn(private, repr(result))
            self.assertTrue(result["pollFallback"]["result"]["path"]["redacted"])
            self.assertTrue(result["pollFallback"]["result"]["nested"][0]["redacted"])
            self.assertEqual(result["pollFallback"]["result"]["address"], "abc")

            def failed_fallback() -> None:
                raise FileNotFoundError(2, "No such file", private)

            failed = hypr_socket2.wait_for_event(
                "openwindow",
                socket_path=missing,
                timeout=0.02,
                reconnect_delay=0.001,
                poll_fallback=failed_fallback,
            )
            self.assertNotIn(private, repr(failed))
            self.assertEqual(failed["pollFallback"]["error"], "FileNotFoundError: No such file")

    def test_fragmented_event_is_reassembled(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "s.sock"
            with FakeSocket2(path, [[
                (0.01, b"openwin"),
                (0.01, b"dow>>cafe,special:tools,Editor,Notes\n"),
            ]]):
                result = hypr_socket2.wait_for_window(
                    {"workspace": "special:tools"}, socket_path=path, timeout=1
                )
        self.assertEqual(result["status"], "matched")
        self.assertEqual(result["details"]["workspace"], "special:tools")

    def test_unrelated_comma_dense_event_is_filtered_before_field_parsing(self) -> None:
        original_parser = hypr_socket2.parse_event_line
        parsed: list[bytes | str] = []

        def tracking_parser(line: bytes | str, *, received_at: float | None = None):
            parsed.append(line)
            return original_parser(line, received_at=received_at)

        hypr_socket2.parse_event_line = tracking_parser
        try:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "s.sock"
                unrelated = b"junk>>" + b"," * 100_000 + b"\n"
                with FakeSocket2(path, [[(0.01, unrelated + b"openwindow>>abc,1,App,Title\n")]]):
                    result = hypr_socket2.wait_for_window(socket_path=path, timeout=1)
        finally:
            hypr_socket2.parse_event_line = original_parser
        self.assertEqual(result["status"], "matched")
        self.assertEqual(parsed, [b"openwindow>>abc,1,App,Title"])

    def test_oversized_line_and_total_stream_fail_closed(self) -> None:
        self.assertEqual(hypr_socket2._MAX_EVENT_LINE_BYTES, 1024 * 1024)
        self.assertEqual(hypr_socket2._MAX_TOTAL_BYTES, 1024 * 1024)
        original_line = hypr_socket2._MAX_EVENT_LINE_BYTES
        original_total = hypr_socket2._MAX_TOTAL_BYTES
        fallback_calls: list[str] = []
        try:
            hypr_socket2._MAX_EVENT_LINE_BYTES = 32
            hypr_socket2._MAX_TOTAL_BYTES = 128
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "line.sock"
                with FakeSocket2(path, [[(0.01, b"x" * 33)]]):
                    with self.assertRaisesRegex(hypr_socket2.Socket2ProtocolError, "event line"):
                        hypr_socket2.wait_for_event(
                            "openwindow",
                            socket_path=path,
                            timeout=1,
                            poll_fallback=lambda: fallback_calls.append("line"),
                        )

            hypr_socket2._MAX_EVENT_LINE_BYTES = 64
            hypr_socket2._MAX_TOTAL_BYTES = 48
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "total.sock"
                chunks = [(0.01, b"workspace>>12345678\n")] * 3
                with FakeSocket2(path, [chunks]):
                    with self.assertRaisesRegex(hypr_socket2.Socket2ProtocolError, "total byte"):
                        hypr_socket2.wait_for_event(
                            "openwindow",
                            socket_path=path,
                            timeout=1,
                            poll_fallback=lambda: fallback_calls.append("total"),
                        )
        finally:
            hypr_socket2._MAX_EVENT_LINE_BYTES = original_line
            hypr_socket2._MAX_TOTAL_BYTES = original_total
        self.assertEqual(fallback_calls, [])

    def test_privacy_safe_event_result_omits_payload_title_class_and_paths(self) -> None:
        digest = "sha256:" + "a" * 64
        private = "/run/user/1000/hypr/private/.socket2.sock"
        value = hypr_socket2.sanitize_event_result({
            "method": "socket2",
            "status": "matched",
            "reconnects": 2,
            "socket": {"source": "explicit", "pathDigest": digest, "path": private},
            "event": {
                "name": "openwindow",
                "payload": "abc,1,Private.App,Secret document",
                "fields": ["abc", "1", "Private.App", "Secret document"],
            },
            "details": {
                "address": "aBc",
                "workspace": "1",
                "class": "Private.App",
                "title": "Secret document",
            },
            "pollFallback": {"result": {"path": private}},
        })
        self.assertEqual(value, {
            "method": "socket2",
            "status": "matched",
            "reconnects": 2,
            "pathDigest": digest,
            "address": "aBc",
        })
        serialized = repr(value)
        for secret in (private, "Private.App", "Secret document", "fields", "payload"):
            self.assertNotIn(secret, serialized)
        self.assertEqual(hypr_socket2.sanitize_event_result({"method": "existing"}), {"method": "existing"})
        self.assertNotIn(
            "address",
            hypr_socket2.sanitize_event_result({
                "method": "poll",
                "pollFallback": {"result": {"address": "deadbeefdeadbeef"}},
            }),
        )
        self.assertNotIn(
            "address",
            hypr_socket2.sanitize_event_result({"details": {"address": "a" * 17}}),
        )

    def test_rejects_symlink_non_socket_and_foreign_owner_before_connect(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            regular = root / "regular"
            regular.write_text("not a socket", encoding="utf-8")
            with self.assertRaisesRegex(hypr_socket2.Socket2ConfigurationError, "Unix socket"):
                hypr_socket2.wait_for_event("openwindow", socket_path=regular, timeout=0.1)

            link = root / "link.sock"
            link.symlink_to(regular)
            with self.assertRaisesRegex(hypr_socket2.Socket2ConfigurationError, "symlink"):
                hypr_socket2.wait_for_event("openwindow", socket_path=link, timeout=0.1)

            socket_path = root / "owned.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                listener.bind(str(socket_path))
                real_getuid = hypr_socket2.os.getuid
                hypr_socket2.os.getuid = lambda: real_getuid() + 1
                try:
                    with self.assertRaisesRegex(hypr_socket2.Socket2ConfigurationError, "current uid"):
                        hypr_socket2.wait_for_event("openwindow", socket_path=socket_path, timeout=0.1)
                finally:
                    hypr_socket2.os.getuid = real_getuid
            finally:
                listener.close()

    def test_validation_uses_lstat_and_fstat_on_the_same_socket_inode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "s.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                listener.bind(str(path))
                identity = hypr_socket2._validate_socket_path(path)
                metadata = path.lstat()
                self.assertTrue(stat.S_ISSOCK(metadata.st_mode))
                self.assertEqual((identity.device, identity.inode), (metadata.st_dev, metadata.st_ino))
            finally:
                listener.close()

    def test_peer_uid_authentication_rejects_a_foreign_peer(self) -> None:
        class ForeignPeer:
            def getsockopt(self, _level: int, _option: int, _size: int) -> bytes:
                return struct.pack("3i", 42, hypr_socket2.os.getuid() + 1, 42)

        with self.assertRaisesRegex(hypr_socket2.Socket2ConfigurationError, "peer.*current uid"):
            hypr_socket2._verify_peer_uid(ForeignPeer())


if __name__ == "__main__":
    unittest.main()
