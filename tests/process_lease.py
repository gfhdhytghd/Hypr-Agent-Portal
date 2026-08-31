#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import multiprocessing
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("process_lease", ROOT / "mcp" / "process_lease.py")
assert SPEC is not None and SPEC.loader is not None
process_lease = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = process_lease
SPEC.loader.exec_module(process_lease)


def _try_lease_in_child(runtime_dir: str, connection: object) -> None:
    lease = process_lease.ProcessMutationLease(runtime_dir=runtime_dir)
    try:
        lease.acquire()
    except process_lease.LeaseConflict as exc:
        connection.send(("conflict", exc.holder))
    else:
        lease.release()
        connection.send(("acquired", {}))
    finally:
        connection.close()


class ProcessMutationLeaseTests(unittest.TestCase):
    def test_lock_conflicts_across_processes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lease = process_lease.ProcessMutationLease(runtime_dir=directory)
            context = multiprocessing.get_context("fork")
            parent_connection, child_connection = context.Pipe(duplex=False)
            with lease.acquire():
                child = context.Process(target=_try_lease_in_child, args=(directory, child_connection))
                child.start()
                child_connection.close()
                status, holder = parent_connection.recv()
                child.join(timeout=5)
            self.assertEqual(child.exitcode, 0)
            self.assertEqual(status, "conflict")
            self.assertEqual(holder["pid"], os.getpid())

    def test_context_manager_serializes_and_reports_safe_holder_details(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = process_lease.ProcessMutationLease(runtime_dir=directory)
            second = process_lease.ProcessMutationLease(runtime_dir=directory)

            with first.acquire() as holder:
                self.assertEqual(holder.pid, os.getpid())
                with self.assertRaises(process_lease.LeaseConflict) as raised:
                    second.acquire()
                self.assertEqual(raised.exception.holder["pid"], os.getpid())
                self.assertEqual(raised.exception.holder["uid"], os.getuid())
                self.assertEqual(raised.exception.holder["instanceId"], first.instance_id)
                self.assertNotIn("environment", raised.exception.holder)
                self.assertNotIn("args", raised.exception.holder)

            with second.acquire():
                self.assertIsNotNone(second.holder)
            self.assertIsNone(second.holder)

    def test_exception_releases_for_the_next_mutation_call(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = process_lease.ProcessMutationLease(runtime_dir=directory)
            second = process_lease.ProcessMutationLease(runtime_dir=directory)
            with self.assertRaisesRegex(RuntimeError, "action failed"):
                with first.acquire():
                    raise RuntimeError("action failed")
            with second.acquire():
                pass

    def test_stale_or_malformed_metadata_never_blocks_an_unlocked_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lease = process_lease.ProcessMutationLease(runtime_dir=directory)
            lease.path.write_text('{"pid":999999,"secret":"do-not-return"}', encoding="utf-8")
            os.chmod(lease.path, 0o600)
            with lease.acquire() as holder:
                current = json.loads(lease.path.read_text(encoding="utf-8"))
                self.assertEqual(current["pid"], holder.pid)
                self.assertNotIn("secret", current)

            lease.path.write_bytes(b"not-json\xff")
            with lease.acquire():
                pass

    def test_metadata_and_paths_are_private(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lease = process_lease.ProcessMutationLease(runtime_dir=directory)
            with lease.acquire():
                metadata = json.loads(lease.path.read_text(encoding="utf-8"))
                self.assertEqual(
                    set(metadata),
                    {"acquiredAt", "instanceId", "pid", "uid"},
                )
                self.assertEqual(stat.S_IMODE(lease.path.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(lease.path.parent.stat().st_mode), 0o700)

    def test_missing_runtime_directory_fails_closed(self) -> None:
        previous = os.environ.pop("XDG_RUNTIME_DIR", None)
        try:
            with self.assertRaises(process_lease.UnsafeLeasePath):
                process_lease.ProcessMutationLease()
        finally:
            if previous is not None:
                os.environ["XDG_RUNTIME_DIR"] = previous

    def test_insecure_runtime_directory_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o755)
            with self.assertRaises(process_lease.UnsafeLeasePath):
                process_lease.ProcessMutationLease(runtime_dir=directory)

    def test_symlink_lock_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = process_lease.resolve_lease_path(directory)
            path.symlink_to(Path(directory) / "elsewhere")
            lease = process_lease.ProcessMutationLease(runtime_dir=directory)
            with self.assertRaises(process_lease.LeaseUnavailable):
                lease.acquire()


if __name__ == "__main__":
    unittest.main()
