"""Unit tests for bin/devrun: the host-side tarball checks, argument handling, names and labels,
the run slots and the exclusive gate, run liveness, and --gc selection.

Run: python3 -m unittest discover -s tests
These tests need no Docker. The lock tests use real flock on files in temporary directories.
"""
import contextlib
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader("devrun", str(ROOT / "bin" / "devrun"))
spec = importlib.util.spec_from_loader("devrun", loader)
devrun = importlib.util.module_from_spec(spec)
loader.exec_module(devrun)


def make_tar(entries):
    """entries: list of (name, kind, extra). kind: file, dir, sym, hard, fifo, chr."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as t:
        for name, kind, extra in entries:
            info = tarfile.TarInfo(name)
            info.uid = info.gid = 0
            info.mode = extra.get("mode", 0o644) if isinstance(extra, dict) else 0o644
            data = None
            if kind == "file":
                payload = extra.get("data", b"x") if isinstance(extra, dict) else b"x"
                info.size = len(payload)
                data = io.BytesIO(payload)
            elif kind == "dir":
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
            elif kind == "sym":
                info.type = tarfile.SYMTYPE
                info.linkname = extra
            elif kind == "hard":
                info.type = tarfile.LNKTYPE
                info.linkname = extra
            elif kind == "fifo":
                info.type = tarfile.FIFOTYPE
            elif kind == "chr":
                info.type = tarfile.CHRTYPE
            t.addfile(info, data)
    buf.seek(0)
    return buf


def sanitize(entries):
    out = io.BytesIO()
    n = devrun.sanitize_tar(make_tar(entries), out)
    out.seek(0)
    return n, out


class SanitizerRefuses(unittest.TestCase):
    def assert_refused(self, entries, needle):
        with self.assertRaises(devrun.DevrunError) as ctx:
            sanitize(entries)
        self.assertIn(needle, str(ctx.exception))

    def test_git_directory(self):
        self.assert_refused([(".git", "dir", None)], ".git")

    def test_nested_git_file(self):
        self.assert_refused([("vendor/lib/.git", "file", {})], ".git")

    def test_absolute_path(self):
        self.assert_refused([("/etc/passwd", "file", {})], "absolute path")

    def test_traversal(self):
        self.assert_refused([("a/../../x", "file", {})], "path traversal")

    def test_absolute_symlink(self):
        self.assert_refused([("link", "sym", "/etc/shadow")], "absolute symlink")

    def test_escaping_symlink(self):
        self.assert_refused([("a/link", "sym", "../../outside")], "escapes")

    def test_symlink_into_git(self):
        self.assert_refused([("link", "sym", ".git/config")], ".git")

    def test_hard_link(self):
        self.assert_refused([("a", "file", {}), ("b", "hard", "a")], "hard link")

    def test_fifo(self):
        self.assert_refused([("pipe", "fifo", None)], "special file")

    def test_device(self):
        self.assert_refused([("dev", "chr", None)], "special file")

    def test_setuid(self):
        self.assert_refused([("bin/tool", "file", {"mode": 0o4755})], "setuid or setgid")

    def test_setgid(self):
        self.assert_refused([("bin/tool", "file", {"mode": 0o2755})], "setuid or setgid")


class SanitizerRewrites(unittest.TestCase):
    def test_owner_and_mode_bits(self):
        n, out = sanitize([("bin/tool", "file", {"mode": 0o1755, "data": b"#!/bin/sh\n"}), ("src", "dir", None)])
        self.assertEqual(n, 2)
        with tarfile.open(fileobj=out) as t:
            members = {m.name: m for m in t.getmembers()}
        tool = members["bin/tool"]
        self.assertEqual((tool.uid, tool.gid), (10001, 10001))
        self.assertEqual(tool.mode, 0o755)
        self.assertEqual(members["src"].uid, 10001)

    def test_inside_symlink_is_kept(self):
        n, _ = sanitize([("a/real", "file", {}), ("a/link", "sym", "real"), ("b/up", "sym", "../a/real")])
        self.assertEqual(n, 3)

    def test_missing_parent_directories_are_emitted_and_owned(self):
        _, out = sanitize([("a/b/c.txt", "file", {}), ("a/d.txt", "file", {})])
        with tarfile.open(fileobj=out) as t:
            members = t.getmembers()
        names = [m.name for m in members]
        self.assertEqual(names, ["a", "a/b", "a/b/c.txt", "a/d.txt"])
        for m in members:
            self.assertEqual((m.uid, m.gid), (10001, 10001))
        self.assertEqual(members[0].type, tarfile.DIRTYPE)

    def test_directory_entries_are_not_duplicated(self):
        _, out = sanitize([("a", "dir", None), ("a/x", "file", {}), ("a", "dir", None)])
        with tarfile.open(fileobj=out) as t:
            self.assertEqual([m.name for m in t.getmembers()], ["a", "a/x"])

    def test_file_content_is_preserved(self):
        _, out = sanitize([("README", "file", {"data": b"hello"})])
        with tarfile.open(fileobj=out) as t:
            self.assertEqual(t.extractfile("README").read(), b"hello")


class ExportChecks(unittest.TestCase):
    def test_regular_files_only(self):
        with tempfile.TemporaryDirectory() as d:
            written = devrun.check_export_tar(make_tar([("out", "dir", None), ("out/hash.txt", "file", {"data": b"h"})]), pathlib.Path(d))
            self.assertEqual(written, ["out/hash.txt"])
            self.assertEqual((pathlib.Path(d) / "out/hash.txt").read_bytes(), b"h")

    def test_symlink_export_refused(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaises(devrun.DevrunError):
            devrun.check_export_tar(make_tar([("evil", "sym", "/etc/passwd")]), pathlib.Path(d))

    def test_existing_file_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            (pathlib.Path(d) / "x").write_text("keep")
            with self.assertRaises(FileExistsError):
                devrun.check_export_tar(make_tar([("x", "file", {"data": b"new"})]), pathlib.Path(d))
            self.assertEqual((pathlib.Path(d) / "x").read_text(), "keep")


class FetchCopy(unittest.TestCase):
    def test_cargo_config_and_toolchain_files_are_excluded_at_every_depth(self):
        for path in [".cargo/config.toml", ".cargo/config", "crates/a/.cargo/config.toml",
                     "rust-toolchain.toml", "rust-toolchain", "crates/a/rust-toolchain.toml"]:
            self.assertTrue(devrun.excluded_from_fetch(path), path)

    def test_lookalikes_are_kept(self):
        for path in ["config.toml", "src/config.toml", ".cargo/credentials.toml", "cargo/config.toml",
                     "docs/rust-toolchain.md", "Cargo.toml", "Cargo.lock"]:
            self.assertFalse(devrun.excluded_from_fetch(path), path)

    def test_fetch_copy_drops_only_excluded_files(self):
        _, clean = sanitize([("Cargo.toml", "file", {}), (".cargo/config.toml", "file", {}),
                             ("rust-toolchain.toml", "file", {}), ("src/main.rs", "file", {})])
        out = io.BytesIO()
        devrun.fetch_copy(clean, out)
        out.seek(0)
        with tarfile.open(fileobj=out) as t:
            names = {m.name for m in t.getmembers() if m.isfile()}
        self.assertEqual(names, {"Cargo.toml", "src/main.rs"})


    def test_fetch_environment_pins_the_compiler_and_clears_wrappers(self):
        env = devrun.fetch_environment({"DEVRUN_HEAD": "abc"}, "1.96.0")
        self.assertEqual(env["RUSTUP_TOOLCHAIN"], "1.96.0")
        self.assertEqual(env["RUSTC"], "/usr/local/cargo/bin/rustc")
        self.assertEqual((env["RUSTC_WRAPPER"], env["RUSTC_WORKSPACE_WRAPPER"]), ("", ""))
        self.assertEqual(env["DEVRUN_HEAD"], "abc")


class FakeDockerCalls(unittest.TestCase):
    """Replaces devrun.run, the process boundary to the docker CLI, with a recorder."""

    def setUp(self):
        self.calls = []
        self.fail_volume_rm = set()
        self.existing_volumes = {}
        self.original_run = devrun.run

        def fake(cmd, **kw):
            self.calls.append(cmd)
            if cmd[:3] == ["docker", "volume", "inspect"]:
                labels = self.existing_volumes.get(cmd[3])
                if labels is None:
                    return devrun.subprocess.CompletedProcess(cmd, 1, b"", b"no such volume")
                return devrun.subprocess.CompletedProcess(cmd, 0, json.dumps(labels).encode(), b"")
            if cmd[:3] == ["docker", "volume", "create"]:
                labels = dict(a.split("=", 1) for a in cmd[4:-1:2])
                self.existing_volumes.setdefault(cmd[-1], labels)
            if cmd[:3] == ["docker", "volume", "rm"] and cmd[3] in self.fail_volume_rm:
                return devrun.subprocess.CompletedProcess(cmd, 1, b"", b"volume is in use")
            return devrun.subprocess.CompletedProcess(cmd, 0, b"", b"")

        devrun.run = fake

    def tearDown(self):
        devrun.run = self.original_run

    def docker(self):
        return devrun.Docker("geordi", RUN_ID, "img", "1", "1g")


RUN_ID = "0123456789ab"
DOCKER_NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]+")


class ResourceNames(unittest.TestCase):
    def test_every_run_resource_is_named_after_the_project_and_the_run(self):
        names = devrun.run_resource_names("geordi", RUN_ID)
        self.assertEqual(names, {"container": "geordi-dev-run-0123456789ab", "work": "geordi-work-0123456789ab",
                                 "scratch": "geordi-scratch-0123456789ab",
                                 "target-evidence": "geordi-target-evidence-0123456789ab"})
        self.assertEqual(set(names) - {"container"}, set(devrun.PER_RUN_ROLES))
        for name in names.values():
            self.assertRegex(name, DOCKER_NAME)

    def test_run_ids_are_twelve_hex_digits_and_differ(self):
        ids = {devrun.new_run_id() for _ in range(200)}
        self.assertEqual(len(ids), 200)
        for rid in ids:
            self.assertRegex(rid, r"^[0-9a-f]{12}$")

    def test_source_key_is_a_stable_hash_of_the_path(self):
        # The value is fixed: a change to the key would orphan every existing target volume.
        self.assertEqual(devrun.source_key("/src/geordi"), hashlib.sha256(b"/src/geordi").hexdigest()[:16])
        self.assertEqual(devrun.source_key("/src/geordi"), devrun.source_key("/src/geordi"))

    def test_a_worktree_has_separate_worktree_and_pinned_targets(self):
        key = devrun.source_key("/src/geordi")
        self.assertEqual(devrun.target_volume_name("geordi", key), f"geordi-target-{key}")
        self.assertEqual(devrun.target_volume_name("geordi", key, "target-pinned"), f"geordi-target-pinned-{key}")

    def test_distinct_worktrees_get_distinct_targets_with_safe_names(self):
        paths = ["/src/geordi", "/src/geordi-2", "/src/geordi/", "/src/a b", "/src/été", "/src/x;rm -rf"]
        names = [devrun.target_volume_name("geordi", devrun.source_key(p)) for p in paths]
        self.assertEqual(len(set(names)), len(paths))
        for name in names:
            self.assertRegex(name, r"^geordi-target-[0-9a-f]{16}$")


class ContainerOwnership(FakeDockerCalls):
    def test_remove_skips_a_container_this_run_did_not_create(self):
        self.docker().remove()
        self.assertEqual(self.calls, [])

    def test_remove_runs_once_after_create(self):
        docker = self.docker()
        docker.create(["true"], False, "geordi-target")
        docker.remove()
        docker.remove()
        self.assertEqual([c for c in self.calls if c[:2] == ["docker", "rm"]], [["docker", "rm", "-f", "geordi-dev-run-0123456789ab"]])

    def test_run_container_mounts_its_own_volumes_with_home_set(self):
        docker = self.docker()
        docker.create(["true"], False, "geordi-target-x")
        create = self.calls[-1]
        self.assertIn("type=volume,src=geordi-work-0123456789ab,dst=/work", create)
        self.assertIn("type=volume,src=geordi-scratch-0123456789ab,dst=/scratch", create)
        self.assertIn("type=volume,src=geordi-target-x,dst=/target", create)
        self.assertIn("HOME=/tmp/home", create)
        self.assertIn("TMPDIR=/exec-tmp", create)
        self.assertIn("/exec-tmp:rw,nosuid,nodev,exec,size=1g,mode=1777", create)
        self.assertEqual(create[create.index("--workdir") + 1], "/work")
        self.assertEqual(create[create.index("--name") + 1], "geordi-dev-run-0123456789ab")

    def test_container_carries_owner_role_and_run_id_labels(self):
        docker = self.docker()
        docker.create(["true"], False, "geordi-target-x")
        create = self.calls[-1]
        labels = {create[i + 1] for i, a in enumerate(create) if a == "--label"}
        self.assertEqual(labels, {"org.flyingrobots.owner=geordi", "org.flyingrobots.role=dev-run",
                                  "org.flyingrobots.run-id=0123456789ab", "org.flyingrobots.phase=command",
                                  "org.flyingrobots.timeout=300"})

    def test_run_volumes_are_labelled_and_removed_by_cleanup(self):
        docker = self.docker()
        docker.create_run_volume("work")
        docker.create_run_volume("scratch")
        self.assertEqual(self.existing_volumes["geordi-work-0123456789ab"],
                         {"org.flyingrobots.owner": "geordi", "org.flyingrobots.role": "work",
                          "org.flyingrobots.run-id": "0123456789ab"})
        self.assertTrue(docker.cleanup())
        removed = [c[3] for c in self.calls if c[:3] == ["docker", "volume", "rm"]]
        self.assertEqual(sorted(removed), ["geordi-scratch-0123456789ab", "geordi-work-0123456789ab"])

    def test_cleanup_never_removes_shared_volumes(self):
        docker = self.docker()
        docker.ensure_volume("geordi-cargo-registry", "cargo-registry")
        docker.ensure_volume("geordi-target-k", "target", {devrun.SOURCE_PATH_LABEL: "/src/g", devrun.SOURCE_KEY_LABEL: "k"})
        self.assertTrue(docker.cleanup())
        self.assertEqual([c for c in self.calls if c[:3] == ["docker", "volume", "rm"]], [])

    def test_cleanup_reports_a_volume_it_could_not_remove(self):
        docker = self.docker()
        docker.create_run_volume("work")
        self.fail_volume_rm.add("geordi-work-0123456789ab")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertFalse(docker.cleanup())

    def test_an_existing_run_volume_is_refused(self):
        self.existing_volumes["geordi-work-0123456789ab"] = {"org.flyingrobots.owner": "other"}
        with self.assertRaises(devrun.DevrunError):
            self.docker().create_run_volume("work")
        self.assertEqual(self.docker().volumes, [])

    def test_a_target_of_another_source_tree_is_refused(self):
        self.existing_volumes["geordi-target-k"] = {"org.flyingrobots.owner": "geordi", "org.flyingrobots.role": "target",
                                                    devrun.SOURCE_PATH_LABEL: "/src/other", devrun.SOURCE_KEY_LABEL: "k"}
        with self.assertRaises(devrun.DevrunError):
            self.docker().ensure_volume("geordi-target-k", "target", {devrun.SOURCE_PATH_LABEL: "/src/g", devrun.SOURCE_KEY_LABEL: "k"})


# --------------------------------------------------------------------------- #
# Slots and the exclusive gate: real flock on files in a temporary directory.
# Each contender is a thread with its own Gate and its own open files, which flock treats like a
# separate process. Time is a fake clock that moves only when a waiter polls; threads synchronize
# on events and on counted poll attempts, never on sleeps.
# --------------------------------------------------------------------------- #

LONG = 10  # seconds; the bound on every event wait, reached only when a test fails


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds
        threading.Event().wait(0.001)  # yield the thread; the fake clock carries the time


class Contender:
    """One run asking for admission in its own thread. `attempts` counts its failed polls."""

    def __init__(self, directory, exclusive, max_runs=4, survivors=None):
        self.clock = FakeClock()
        self.attempts = 0
        self.messages = []
        self.changed = threading.Condition()
        self.admitted = threading.Event()
        self.let_go = threading.Event()
        self.done = threading.Event()
        self.error = None
        self.gate = devrun.Gate(directory, max_runs, clock=self.clock, sleep=self.clock.sleep,
                                report=self._report, poll=0.5, report_every=0.5, survivors=survivors)
        self.thread = threading.Thread(target=self._run, args=(exclusive,), daemon=True)
        self.thread.start()

    def _report(self, msg):
        with self.changed:
            self.messages.append(msg)
            self.attempts += 1
            self.changed.notify_all()

    def _run(self, exclusive):
        try:
            with self.gate.admit(exclusive, None):
                self.admitted.set()
                self.let_go.wait(LONG)
        except BaseException as exc:  # reported to the test
            self.error = exc
        finally:
            self.done.set()

    def wait_attempts(self, n):
        """Block until this contender has failed at least n more polls than it had so far."""
        with self.changed:
            target = self.attempts + n
            if not self.changed.wait_for(lambda: self.attempts >= target, LONG):
                raise AssertionError("contender stopped polling")

    def release(self):
        self.let_go.set()
        if not self.done.wait(LONG):
            raise AssertionError("contender did not finish")
        if self.error:
            raise self.error


class GateCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        self.contenders = []

    def tearDown(self):
        for c in self.contenders:
            c.let_go.set()
            c.done.wait(LONG)
        self.tmp.cleanup()

    def contender(self, exclusive=False, max_runs=4):
        c = Contender(self.dir, exclusive, max_runs)
        self.contenders.append(c)
        return c

    def admitted(self, c):
        self.assertTrue(c.admitted.wait(LONG), "contender was not admitted")
        self.assertIsNone(c.error)

    def try_once(self, exclusive=False, max_runs=1):
        """Admission with a zero wait limit: succeeds only if admission is possible right now."""
        gate = devrun.Gate(self.dir, max_runs, clock=FakeClock(), sleep=lambda s: None, report=lambda m: None)
        return gate.admit(exclusive, 0)


class Slots(GateCase):
    def test_the_cap_admits_n_runs_and_the_next_waits_for_a_release(self):
        a, b = self.contender(max_runs=2), self.contender(max_runs=2)
        self.admitted(a)
        self.admitted(b)
        c = self.contender(max_runs=2)
        c.wait_attempts(3)
        self.assertFalse(c.admitted.is_set())
        a.release()
        self.admitted(c)

    def test_a_slot_is_released_when_the_run_raises(self):
        gate = devrun.Gate(self.dir, 1)
        with self.assertRaises(ValueError):
            with gate.admit(False, 0):
                raise ValueError("command failed")
        self.try_once().release()

    def test_the_cap_is_held_while_admitted(self):
        with self.try_once():
            with self.assertRaises(devrun.DevrunError) as ctx:
                self.try_once()
        self.assertIn("gave up after waiting 0 s for a run slot", str(ctx.exception))

    def test_a_waiting_run_reports_how_long_it_has_waited_and_gives_up_at_the_limit(self):
        messages = []
        clock = FakeClock()
        gate = devrun.Gate(self.dir, 1, clock=clock, sleep=lambda s: setattr(clock, "now", clock.now + s),
                           report=messages.append, poll=0.5, report_every=30)
        with self.try_once():
            with self.assertRaises(devrun.DevrunError) as ctx:
                gate.admit(False, 61)
        self.assertEqual(len(messages), 3)
        for msg, waited in zip(messages, (0, 30, 60)):
            self.assertTrue(msg.startswith("devrun: waiting for a run slot"), msg)
            self.assertIn(f"waited {waited} s so far", msg)
        self.assertIn("gave up after waiting 61 s", str(ctx.exception))

    def test_a_slot_held_by_a_killed_process_is_free_again(self):
        child = subprocess.Popen([sys.executable, "-c", HOLD_SLOT, str(ROOT / "bin" / "devrun"), str(self.dir)],
                                 stdout=subprocess.PIPE, stdin=subprocess.PIPE)
        try:
            self.assertEqual(child.stdout.readline(), b"admitted\n")
            with self.assertRaises(devrun.DevrunError):
                self.try_once()
        finally:
            child.kill()
            child.wait()
            child.stdin.close()
            child.stdout.close()
        self.try_once().release()

    def test_the_cap_is_validated(self):
        for bad in (0, devrun.MAX_RUNS_LIMIT + 1):
            with self.assertRaises(devrun.DevrunError):
                devrun.Gate(self.dir, bad)


HOLD_SLOT = """
import importlib.machinery, importlib.util, pathlib, sys
loader = importlib.machinery.SourceFileLoader("devrun", sys.argv[1])
spec = importlib.util.spec_from_loader("devrun", loader)
devrun = importlib.util.module_from_spec(spec)
loader.exec_module(devrun)
held = devrun.Gate(pathlib.Path(sys.argv[2]), 1).admit(False, 0)
print("admitted", flush=True)
sys.stdin.read()
"""


class ExclusiveGate(GateCase):
    def test_an_exclusive_run_waits_for_admitted_ordinary_runs(self):
        a = self.contender()
        self.admitted(a)
        e = self.contender(exclusive=True)
        e.wait_attempts(3)
        self.assertFalse(e.admitted.is_set())
        a.release()
        self.admitted(e)

    def test_ordinary_runs_wait_while_an_exclusive_run_holds_the_machine(self):
        e = self.contender(exclusive=True)
        self.admitted(e)
        b = self.contender()
        b.wait_attempts(3)
        self.assertFalse(b.admitted.is_set())
        e.release()
        self.admitted(b)

    def test_a_waiting_exclusive_run_is_not_starved_by_new_ordinary_runs(self):
        a = self.contender()
        self.admitted(a)
        e = self.contender(exclusive=True)
        e.wait_attempts(2)
        # Three of four slots are free, but an exclusive run is queued: new runs queue behind it.
        b, c = self.contender(), self.contender()
        b.wait_attempts(3)
        c.wait_attempts(3)
        self.assertFalse(b.admitted.is_set() or c.admitted.is_set())
        a.release()
        self.admitted(e)
        b.wait_attempts(2)
        self.assertFalse(b.admitted.is_set() or c.admitted.is_set())
        e.release()
        self.admitted(b)
        self.admitted(c)

    def test_two_exclusive_runs_take_turns(self):
        e1 = self.contender(exclusive=True)
        self.admitted(e1)
        e2 = self.contender(exclusive=True)
        e2.wait_attempts(3)
        self.assertFalse(e2.admitted.is_set())
        e1.release()
        self.admitted(e2)

    def test_the_exclusive_hold_is_released_when_the_run_raises(self):
        gate = devrun.Gate(self.dir, 1)
        with self.assertRaises(ValueError):
            with gate.admit(True, 0):
                raise ValueError("benchmark failed")
        self.try_once(exclusive=False).release()
        self.try_once(exclusive=True).release()

    def test_an_exclusive_run_that_gives_up_lets_ordinary_runs_in(self):
        with self.try_once():
            with self.assertRaises(devrun.DevrunError):
                self.try_once(exclusive=True)
            # The failed exclusive request must not leave the turnstile held.
        self.try_once().release()


class NamedLocks(GateCase):
    def test_a_project_fetch_lock_admits_one_holder(self):
        gate = devrun.Gate(self.dir, 1, clock=FakeClock(), sleep=lambda s: None, report=lambda m: None)
        with gate.hold("fetch-geordi.lock", "the fetch lock", 0):
            with self.assertRaises(devrun.DevrunError):
                gate.hold("fetch-geordi.lock", "the fetch lock", 0)
            gate.hold("fetch-bunny.lock", "the fetch lock", 0).release()
        gate.hold("fetch-geordi.lock", "the fetch lock", 0).release()


class Liveness(GateCase):
    def setUp(self):
        super().setUp()
        (self.dir / "runs").mkdir()

    def test_a_run_is_alive_while_its_record_is_held(self):
        record = devrun.RunRecord(self.dir, RUN_ID, {"project": "geordi"})
        self.assertEqual(devrun.run_liveness(self.dir, RUN_ID), "alive")
        record.finish(clean=True)
        self.assertEqual(devrun.run_liveness(self.dir, RUN_ID), "unknown")

    def test_a_run_that_could_not_clean_up_is_dead_after_it_finishes(self):
        devrun.RunRecord(self.dir, RUN_ID, {"project": "geordi"}).finish(clean=False)
        self.assertEqual(devrun.run_liveness(self.dir, RUN_ID), "dead")

    def test_a_killed_run_is_dead(self):
        child = subprocess.Popen([sys.executable, "-c", HOLD_RECORD, str(ROOT / "bin" / "devrun"), str(self.dir), RUN_ID],
                                 stdout=subprocess.PIPE, stdin=subprocess.PIPE)
        try:
            self.assertEqual(child.stdout.readline(), b"recorded\n")
            self.assertEqual(devrun.run_liveness(self.dir, RUN_ID), "alive")
            self.assertEqual(devrun.live_run_facts(self.dir), [{"project": "geordi", "source_key": "k"}])
        finally:
            child.kill()
            child.wait()
            child.stdin.close()
            child.stdout.close()
        self.assertEqual(devrun.run_liveness(self.dir, RUN_ID), "dead")
        self.assertEqual(devrun.live_run_facts(self.dir), [])

    def test_a_dead_run_stays_dead_while_another_probe_looks_at_it(self):
        # Review of #13: two probes at once. The other probe holds its (shared) lock on the record.
        devrun.RunRecord(self.dir, RUN_ID, {"project": "geordi"}).finish(clean=False)
        other = os.open(str(self.dir / "runs" / f"{RUN_ID}.lock"), os.O_RDWR)
        try:
            devrun.fcntl.flock(other, devrun.fcntl.LOCK_SH | devrun.fcntl.LOCK_NB)
            self.assertEqual(devrun.run_liveness(self.dir, RUN_ID), "dead")
        finally:
            os.close(other)

    def test_concurrent_probes_of_a_dead_run_all_see_it_dead(self):
        devrun.RunRecord(self.dir, RUN_ID, {"project": "geordi"}).finish(clean=False)
        results, start = [], threading.Barrier(8)

        def probe():
            start.wait(LONG)
            for _ in range(200):
                results.append(devrun.run_liveness(self.dir, RUN_ID))
        threads = [threading.Thread(target=probe) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(LONG)
        self.assertEqual(set(results), {"dead"})

    def test_an_unknown_run_is_not_dead(self):
        self.assertEqual(devrun.run_liveness(self.dir, "aaaaaaaaaaaa"), "unknown")

    def test_a_run_id_cannot_be_recorded_twice(self):
        record = devrun.RunRecord(self.dir, RUN_ID, {})
        try:
            with self.assertRaises(devrun.DevrunError):
                devrun.RunRecord(self.dir, RUN_ID, {})
        finally:
            record.finish(clean=True)


HOLD_RECORD = """
import importlib.machinery, importlib.util, pathlib, sys
loader = importlib.machinery.SourceFileLoader("devrun", sys.argv[1])
spec = importlib.util.spec_from_loader("devrun", loader)
devrun = importlib.util.module_from_spec(spec)
loader.exec_module(devrun)
record = devrun.RunRecord(pathlib.Path(sys.argv[2]), sys.argv[3], {"project": "geordi", "source_key": "k"})
print("recorded", flush=True)
sys.stdin.read()
"""


# --------------------------------------------------------------------------- #
# --gc selection
# --------------------------------------------------------------------------- #

LIVE, DEAD = "aaaaaaaaaaaa", "dddddddddddd"
KEY_GONE = devrun.source_key("/src/deleted")
KEY_HERE = devrun.source_key("/src/present")


def labels(role, run_id=None, owner="geordi", **extra):
    out = {devrun.OWNER_LABEL: owner, devrun.ROLE_LABEL: role}
    if run_id:
        out[devrun.RUN_ID_LABEL] = run_id
    out.update(extra)
    return out


def container(run_id, running=False, owner="geordi", name=None, mounts=None, label_run_id=None):
    names = devrun.run_resource_names("geordi", run_id)
    return {"name": name or names["container"], "running": running,
            "labels": labels("dev-run", label_run_id or run_id, owner),
            "mounts": [names["work"], names["scratch"]] if mounts is None else mounts}


def run_volumes(run_id):
    names = devrun.run_resource_names("geordi", run_id)
    return [{"name": names[r], "labels": labels(r, run_id)} for r in devrun.PER_RUN_ROLES]


def target(path, key=None, name=None, role="target"):
    key = key or devrun.source_key(path)
    return {"name": name or devrun.target_volume_name("geordi", key, role),
            "labels": labels(role, **{devrun.SOURCE_PATH_LABEL: path, devrun.SOURCE_KEY_LABEL: key})}


class GcSelection(unittest.TestCase):
    def plan(self, containers, volumes, protected=frozenset()):
        return devrun.plan_gc("geordi", containers, volumes,
                              liveness=lambda rid: {LIVE: "alive", DEAD: "dead"}.get(rid, "unknown"),
                              path_exists=lambda p: p == "/src/present",
                              protected_keys=None if protected is None else set(protected))

    def test_a_dead_runs_stopped_container_and_volumes_are_selected(self):
        plan = self.plan([container(DEAD)], run_volumes(DEAD))
        self.assertEqual(plan["containers"], ["geordi-dev-run-dddddddddddd"])
        self.assertEqual(sorted(plan["volumes"]), sorted(v["name"] for v in run_volumes(DEAD)))

    def test_a_live_runs_resources_are_never_selected(self):
        # A live run between phases has a stopped container, or none at all.
        for containers in ([container(LIVE)], []):
            plan = self.plan(containers, run_volumes(LIVE))
            self.assertEqual((plan["containers"], plan["volumes"]), ([], []))

    def test_a_run_of_unknown_state_is_never_selected(self):
        plan = self.plan([container("eeeeeeeeeeee")], run_volumes("eeeeeeeeeeee"))
        self.assertEqual((plan["containers"], plan["volumes"]), ([], []))

    def test_a_dead_runs_running_container_and_its_volumes_are_kept(self):
        plan = self.plan([container(DEAD, running=True)], run_volumes(DEAD))
        self.assertEqual(plan["containers"], [])
        self.assertEqual(plan["volumes"], [devrun.run_resource_names("geordi", DEAD)["target-evidence"]])
        self.assertTrue(any("still running" in reason for _, reason in plan["kept"]))

    def test_a_dead_runs_volume_used_by_a_foreign_container_is_kept(self):
        foreign = {"name": "other-thing", "running": False, "labels": {}, "mounts": [devrun.run_resource_names("geordi", DEAD)["work"]]}
        plan = self.plan([foreign], run_volumes(DEAD))
        self.assertNotIn("geordi-work-dddddddddddd", plan["volumes"])

    def test_unlabelled_and_foreign_resources_are_never_selected(self):
        containers = [
            {"name": "geordi-dev-run-dddddddddddd", "running": False, "labels": {}, "mounts": []},
            container(DEAD, owner="bunny"),
            {"name": "geordi-dev-run", "running": False, "labels": labels("dev-run"), "mounts": []},
            container(DEAD, name="geordi-dev-run-ffffffffffff"),  # name and run-id label disagree
            container(DEAD, label_run_id="not-a-run-id", name="geordi-dev-run-not-a-run-id"),
        ]
        volumes = [
            {"name": "geordi-work-dddddddddddd", "labels": {}},
            {"name": "geordi-scratch-dddddddddddd", "labels": labels("scratch", DEAD, owner="bunny")},
            {"name": "geordi-work", "labels": labels("work")},
            {"name": "geordi-target", "labels": labels("target")},
            {"name": "geordi-target-evidence", "labels": labels("target-evidence")},
            {"name": "geordi-cargo-registry", "labels": labels("cargo-registry", DEAD)},
            {"name": "geordi-cargo-git", "labels": labels("cargo-git")},
            {"name": "geordi-work-ffffffffffff", "labels": labels("work", DEAD)},
        ]
        plan = self.plan(containers, volumes)
        self.assertEqual((plan["containers"], plan["volumes"]), ([], []))

    def test_the_target_of_a_deleted_worktree_is_selected_and_an_existing_one_kept(self):
        plan = self.plan([], [target("/src/deleted"), target("/src/present")])
        self.assertEqual(plan["volumes"], [devrun.target_volume_name("geordi", KEY_GONE)])

    def test_a_target_whose_labels_do_not_match_its_name_is_kept(self):
        plan = self.plan([], [target("/src/deleted", key=KEY_HERE),
                              target("/src/deleted", name="geordi-target-0000000000000000"),
                              {"name": devrun.target_volume_name("geordi", KEY_GONE),
                               "labels": labels("target", **{devrun.SOURCE_KEY_LABEL: KEY_GONE})}])
        self.assertEqual(plan["volumes"], [])

    def test_the_pinned_target_of_a_deleted_worktree_is_selected_and_an_existing_one_kept(self):
        plan = self.plan([], [target("/src/deleted", role="target-pinned"), target("/src/present", role="target-pinned")])
        self.assertEqual(plan["volumes"], ["geordi-target-pinned-" + KEY_GONE])

    def test_a_pinned_target_named_like_a_worktree_target_is_kept(self):
        # Role and name must agree: a pinned-role volume under the worktree target's name, and the reverse.
        plan = self.plan([], [target("/src/deleted", role="target-pinned", name=devrun.target_volume_name("geordi", KEY_GONE)),
                              target("/src/deleted", name="geordi-target-pinned-" + KEY_GONE)])
        self.assertEqual(plan["volumes"], [])

    def test_a_target_in_use_is_kept(self):
        name = devrun.target_volume_name("geordi", KEY_GONE)
        user = {"name": "geordi-dev-run-aaaaaaaaaaaa", "running": False, "labels": labels("dev-run", LIVE), "mounts": [name]}
        self.assertEqual(self.plan([user], [target("/src/deleted")])["volumes"], [])
        self.assertEqual(self.plan([], [target("/src/deleted")], protected={KEY_GONE})["volumes"], [])
        self.assertEqual(self.plan([], [target("/src/deleted")], protected=None)["volumes"], [])


# --------------------------------------------------------------------------- #
# git-locks registration: a fake git-locks executable at the process boundary
# --------------------------------------------------------------------------- #


class LeaseRegistration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        self.waits = 0

    def tearDown(self):
        self.tmp.cleanup()

    def fake_git_locks(self, exit_codes):
        """A git-locks that records its arguments and exits with the next code in the list."""
        script = self.dir / "git-locks"
        (self.dir / "codes").write_text("".join(f"{c}\n" for c in exit_codes))
        script.write_text("#!/bin/sh\n"
                          f'echo "$*" >> "{self.dir}/calls"\n'
                          f'n=$(wc -l < "{self.dir}/calls" | tr -d " ")\n'
                          f'code=$(sed -n "${{n}}p" "{self.dir}/codes")\n'
                          'exit "${code:-0}"\n')
        script.chmod(0o755)
        return str(script)

    def calls(self):
        return (self.dir / "calls").read_text().splitlines()

    def lease(self, executable):
        return devrun.Lease("devrun-geordi-x", "devrun-x", "host/docker/geordi-dev-run-x/", 100, "note", executable, env={})

    def waiter(self):
        def count(_s):
            self.waits += 1
        return devrun.Waiter("lock", None, FakeClock(), count, lambda m: None, 1, 30)

    def test_a_claimed_key_is_released_at_the_end(self):
        lease = self.lease(self.fake_git_locks([0, 0]))
        self.assertTrue(lease.claim(self.waiter()))
        lease.release()
        lease.release()
        claim, release = self.calls()
        self.assertIn("claim --job devrun-geordi-x --holder devrun-x --ttl 100", claim)
        self.assertTrue(claim.endswith("host/docker/geordi-dev-run-x/"))
        self.assertEqual(release, "release --job devrun-geordi-x")
        self.assertEqual(lease.env["GIT_LOCKS_STORE"], devrun.LOCK_STORE)

    def test_a_refusal_waits_and_retries(self):
        lease = self.lease(self.fake_git_locks([1, 1, 0]))
        self.assertTrue(lease.claim(self.waiter()))
        self.assertEqual(self.waits, 2)

    def test_a_broken_or_missing_git_locks_does_not_stop_the_run(self):
        for executable in (self.fake_git_locks([2]), "", str(self.dir / "absent")):
            with contextlib.redirect_stderr(io.StringIO()) as err:
                lease = self.lease(executable)
                self.assertFalse(lease.claim(self.waiter()))
                lease.release()
            self.assertIn("devrun: git-locks", err.getvalue())
        self.assertEqual(len(self.calls()), 1)  # the one failed claim, and no release after it


class StateDirectory(unittest.TestCase):
    def test_created_private_with_a_runs_directory(self):
        with tempfile.TemporaryDirectory() as d:
            path = devrun.state_dir({devrun.STATE_ENV: f"{d}/state"})
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode) & 0o077, 0)
            self.assertTrue((path / "runs").is_dir())

    def test_a_directory_writable_by_others_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            os.chmod(d, 0o777)
            with self.assertRaises(devrun.DevrunError):
                devrun.state_dir({devrun.STATE_ENV: d})

    def test_default_follows_xdg_state_home(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(devrun.state_dir({"XDG_STATE_HOME": d}), pathlib.Path(d) / "devrun")


class Arguments(unittest.TestCase):
    def test_requires_double_dash(self):
        with self.assertRaises(devrun.DevrunError):
            devrun.parse_args(["geordi", ".", "--commit", "HEAD", "true"])

    def test_requires_command(self):
        with self.assertRaises(devrun.DevrunError):
            devrun.parse_args(["geordi", ".", "--commit", "HEAD", "--"])

    def test_project_name_is_strict(self):
        for bad in ["Geordi", "../x", "a b", "", "-x"]:
            with self.assertRaises((devrun.DevrunError, SystemExit)):
                devrun.parse_args([bad, ".", "--commit", "HEAD", "--", "true"])

    def test_one_source_mode(self):
        with self.assertRaises(SystemExit):
            devrun.parse_args(["geordi", ".", "--commit", "HEAD", "--worktree", "--", "true"])

    def test_export_paths_are_checked(self):
        with self.assertRaises(devrun.DevrunError):
            devrun.parse_args(["geordi", ".", "--commit", "HEAD", "--export", "../../etc", "--", "true"])

    def test_run_cap_flag_environment_and_bounds(self):
        base = ["geordi", ".", "--commit", "HEAD"]
        saved = devrun.os.environ.get(devrun.MAX_RUNS_ENV)
        try:
            devrun.os.environ.pop(devrun.MAX_RUNS_ENV, None)
            self.assertEqual(devrun.parse_args(base + ["--", "true"]).max_runs, 4)
            devrun.os.environ[devrun.MAX_RUNS_ENV] = "2"
            self.assertEqual(devrun.parse_args(base + ["--", "true"]).max_runs, 2)
            self.assertEqual(devrun.parse_args(base + ["--max-runs", "1", "--", "true"]).max_runs, 1)
            for bad in ("x", "-1", "0", "65"):
                devrun.os.environ[devrun.MAX_RUNS_ENV] = bad
                with self.assertRaises(devrun.DevrunError):
                    devrun.parse_args(base + ["--", "true"])
        finally:
            if saved is None:
                devrun.os.environ.pop(devrun.MAX_RUNS_ENV, None)
            else:
                devrun.os.environ[devrun.MAX_RUNS_ENV] = saved

    def test_exclusive_and_wait(self):
        ns = devrun.parse_args(["geordi", ".", "--commit", "HEAD", "--exclusive", "--wait", "0", "--", "true"])
        self.assertTrue(ns.exclusive)
        self.assertEqual(ns.wait, 0)
        with self.assertRaises(devrun.DevrunError):
            devrun.parse_args(["geordi", ".", "--commit", "HEAD", "--wait", "-1", "--", "true"])

    def test_good_arguments(self):
        ns = devrun.parse_args(["geordi", ".", "--commit", "HEAD", "--fetch", "--export", "hashes.txt", "--", "cargo", "test"])
        self.assertEqual(ns.command, ["cargo", "test"])
        self.assertTrue(ns.fetch)


# --------------------------------------------------------------------------- #
# A fake Docker daemon at the process boundary (devrun.run), for error paths that real Docker
# cannot be made to produce on demand: interrupted creates, failing inspects, and orderings
# around a signal. Other commands (git) run for real; git-locks is never called.
# --------------------------------------------------------------------------- #


def _done(cmd, code=0, out=b"", err=b""):
    return devrun.subprocess.CompletedProcess(cmd, code, out, err)


class FakeDaemon:
    """Containers and volumes in dictionaries. `hooks` maps a command prefix (a tuple) to a function
    called with the command before the daemon acts on it; it may raise, change `self`, or return a
    CompletedProcess to use instead of the daemon's own answer."""

    def __init__(self):
        self.volumes = {}      # name -> labels
        self.containers = {}   # name -> {"id", "labels", "running", "mounts", "started"}
        self.hooks = {}
        self.after = {}        # like hooks, called after the daemon acted, with (cmd, result)
        self.calls = []
        self.now = "2026-11-14T03:00:00.000000000Z"
        self.serial = 0
        self.real_run = devrun.run

    def install(self, case):
        devrun.run = self
        case.addCleanup(setattr, devrun, "run", self.real_run)

    def add_container(self, name, labels, running=True, mounts=(), started="2026-11-14T02:00:00.5Z"):
        self.serial += 1
        self.containers[name] = {"id": f"{self.serial:064x}", "labels": dict(labels), "running": running,
                                 "mounts": list(mounts), "started": started}
        return self.containers[name]["id"]

    def by_ref(self, ref):
        for name, c in self.containers.items():
            if ref in (name, c["id"]):
                return name
        return None

    def __call__(self, cmd, **kw):
        if cmd and os.path.basename(cmd[0]) == "git-locks":
            return _done(cmd, 0)
        if not cmd or cmd[0] != "docker":
            return self.real_run(cmd, **kw)
        self.calls.append(cmd)
        for prefix, hook in self.hooks.items():
            if tuple(cmd[:len(prefix)]) == prefix:
                result = hook(cmd)
                if result is not None:
                    return result
        result = self.act(cmd)
        for prefix, hook in self.after.items():
            if tuple(cmd[:len(prefix)]) == prefix:
                hook(cmd, result)
        return result

    @staticmethod
    def filters(cmd):
        out = []
        for i, a in enumerate(cmd):
            if a == "--filter":
                out.append(cmd[i + 1])
        return out

    @staticmethod
    def matches(labels, name, filters):
        for f in filters:
            kind, _, value = f.partition("=")
            if kind == "label":
                k, eq, v = value.partition("=")
                if k not in labels or (eq and labels[k] != v):
                    return False
            elif kind == "name":
                if not re.search(value, name):
                    return False
        return True

    def act(self, cmd):
        args = cmd[1:]
        if args[:2] == ["volume", "inspect"]:
            if "--format" in args:
                labels = self.volumes.get(args[2])
                return _done(cmd, 1, b"", b"no such volume") if labels is None else _done(cmd, 0, json.dumps(labels).encode())
            names = args[2:]
            found = [{"Name": n, "Labels": self.volumes[n]} for n in names if n in self.volumes]
            return _done(cmd, 0 if len(found) == len(names) else 1, json.dumps(found).encode() if found else b"")
        if args[:2] == ["volume", "create"]:
            labels = dict(a.split("=", 1) for a in args[3:-1:2])
            self.volumes.setdefault(args[-1], labels)
            return _done(cmd, 0, args[-1].encode())
        if args[:2] == ["volume", "rm"]:
            if args[2] not in self.volumes:
                return _done(cmd, 1, b"", b"no such volume")
            if any(args[2] in c["mounts"] for c in self.containers.values()):
                return _done(cmd, 1, b"", b"volume is in use")
            del self.volumes[args[2]]
            return _done(cmd, 0)
        if args[:2] == ["volume", "ls"]:
            names = [n for n, l in sorted(self.volumes.items()) if self.matches(l, n, self.filters(cmd))]
            return _done(cmd, 0, "".join(n + "\n" for n in names).encode())
        if args[0] == "ps":
            every = "-a" in args or "-aq" in args
            rows = [(n, c) for n, c in sorted(self.containers.items())
                    if (every or c["running"]) and self.matches(c["labels"], n, self.filters(cmd))]
            names = "--format" in args
            return _done(cmd, 0, "".join((n if names else c["id"]) + "\n" for n, c in rows).encode())
        if args[:2] == ["container", "inspect"] or args[0] == "inspect":
            refs = args[2:] if args[0] == "container" else args[1:]
            if "--format" in refs:
                name = self.by_ref(refs[-1])
                if name is None:
                    return _done(cmd, 1, b"", b"No such container")
                return _done(cmd, 0, b"true\n" if self.containers[name]["running"] else b"false\n")
            found = []
            for ref in refs:
                name = self.by_ref(ref)
                if name is not None:
                    c = self.containers[name]
                    found.append({"Id": c["id"], "Name": "/" + name, "Config": {"Labels": c["labels"]},
                                  "State": {"Running": c["running"], "StartedAt": c["started"]},
                                  "Mounts": [{"Type": "volume", "Name": m} for m in c["mounts"]]})
            return _done(cmd, 0 if len(found) == len(refs) else 1, json.dumps(found).encode() if found else b"")
        if args[0] == "create":
            name = args[args.index("--name") + 1]
            if name in self.containers:
                return _done(cmd, 1, b"", b"Conflict")
            labels = dict(args[i + 1].split("=", 1) for i, a in enumerate(args) if a == "--label")
            mounts = [re.search(r"src=([^,]+)", args[i + 1]).group(1) for i, a in enumerate(args) if a == "--mount"]
            self.add_container(name, labels, running=False, mounts=mounts)
            self.containers[name]["cmd"] = list(args)
            return _done(cmd, 0)
        if args[0] == "start":
            name = self.by_ref(args[-1])
            if name is None:
                return _done(cmd, 1, b"", b"No such container")
            self.containers[name]["running"] = False
            return _done(cmd, 0)
        if args[0] in ("kill", "stop"):
            name = self.by_ref(args[-1])
            if name is None:
                return _done(cmd, 1, b"", b"No such container")
            self.containers[name]["running"] = False
            return _done(cmd, 0)
        if args[0] == "wait":
            return _done(cmd, 0 if self.by_ref(args[-1]) else 1, b"137\n")
        if args[0] == "rm":
            name = self.by_ref(args[-1])
            if name is None:
                return _done(cmd, 1, b"", b"No such container")
            if self.containers[name]["running"] and "-f" not in args:
                return _done(cmd, 1, b"", b"container is running")
            del self.containers[name]
            return _done(cmd, 0)
        if args[0] == "info":
            return _done(cmd, 0, json.dumps(self.now).encode())
        if args[0] == "cp":
            return _done(cmd, 0)
        raise AssertionError(f"the fake daemon does not know {cmd}")


def interrupt(*_):
    raise devrun.DevrunError("interrupted by signal 15; removing this run's container and volumes")


class InterruptedCreates(unittest.TestCase):
    """Finding 3: a signal between Docker's create and devrun's bookkeeping."""

    def setUp(self):
        self.daemon = FakeDaemon()
        self.daemon.install(self)
        self.docker = devrun.Docker("geordi", RUN_ID, "img", "1", "1g")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = pathlib.Path(self.tmp.name)
        (self.dir / "runs").mkdir()

    def test_a_volume_created_just_before_a_signal_is_removed_by_cleanup(self):
        self.daemon.after[("docker", "volume", "create")] = interrupt
        with self.assertRaises(devrun.DevrunError):
            self.docker.create_run_volume("work")
        self.assertIn("geordi-work-0123456789ab", self.daemon.volumes)
        self.assertTrue(self.docker.cleanup())
        self.assertEqual(self.daemon.volumes, {})

    def test_a_signal_before_docker_created_the_volume_leaves_nothing_to_remove(self):
        self.daemon.hooks[("docker", "volume", "create")] = interrupt
        with self.assertRaises(devrun.DevrunError):
            self.docker.create_run_volume("work")
        self.assertTrue(self.docker.cleanup())
        self.assertNotIn(["docker", "volume", "rm", "geordi-work-0123456789ab"], self.daemon.calls)

    def test_the_record_is_kept_when_cleanup_cannot_tell_whether_a_volume_exists(self):
        record = devrun.RunRecord(self.dir, RUN_ID, {"project": "geordi"})
        self.daemon.after[("docker", "volume", "create")] = interrupt
        with self.assertRaises(devrun.DevrunError):
            self.docker.create_run_volume("scratch")
        self.daemon.hooks[("docker", "volume", "ls")] = lambda cmd: _done(cmd, 1, b"", b"daemon unavailable")
        self.daemon.hooks[("docker", "volume", "rm")] = lambda cmd: _done(cmd, 1, b"", b"daemon unavailable")
        with contextlib.redirect_stderr(io.StringIO()):
            clean = self.docker.cleanup()
        record.finish(clean)
        self.assertFalse(clean)
        self.assertEqual(devrun.run_liveness(self.dir, RUN_ID), "dead")  # --gc still finds the run

    def test_a_volume_of_another_owner_under_the_runs_name_is_never_removed(self):
        # The create is interrupted and the name turns out to belong to a volume without this run's labels.
        def foreign(cmd):
            self.daemon.volumes[cmd[-1]] = {devrun.OWNER_LABEL: "someone-else"}
            interrupt()
        self.daemon.hooks[("docker", "volume", "create")] = foreign
        with self.assertRaises(devrun.DevrunError):
            self.docker.create_run_volume("work")
        self.assertTrue(self.docker.cleanup())
        self.assertIn("geordi-work-0123456789ab", self.daemon.volumes)

    def test_a_container_created_just_before_a_signal_is_removed_by_cleanup(self):
        self.daemon.after[("docker", "create")] = interrupt
        with self.assertRaises(devrun.DevrunError):
            self.docker.create(["true"], False, "geordi-target-x")
        self.assertIn(self.docker.name, self.daemon.containers)
        self.assertTrue(self.docker.cleanup())
        self.assertEqual(self.daemon.containers, {})

    def test_a_failed_create_under_a_foreign_containers_name_does_not_remove_it(self):
        self.daemon.add_container("geordi-dev-run-0123456789ab", {devrun.OWNER_LABEL: "other"}, running=True)
        with self.assertRaises(devrun.DevrunError):
            self.docker.create(["true"], False, "geordi-target-x")
        self.assertTrue(self.docker.cleanup())
        self.assertIn("geordi-dev-run-0123456789ab", self.daemon.containers)
        self.assertFalse(any(c[:2] == ["docker", "rm"] for c in self.daemon.calls))


class InspectFailures(unittest.TestCase):
    """Finding 4: a failing docker inspect must not make existing resources look absent."""

    def setUp(self):
        self.daemon = FakeDaemon()
        self.daemon.install(self)

    def test_an_inspect_that_fails_while_the_resources_still_exist_raises(self):
        cid = self.daemon.add_container("geordi-dev-run-dddddddddddd", labels("dev-run", "dddddddddddd"), running=False)
        self.daemon.hooks[("docker", "container", "inspect")] = lambda cmd: _done(cmd, 1, b"", b"daemon error")
        with self.assertRaises(devrun.DevrunError) as ctx:
            devrun._inspect(["container"], [cid], devrun.all_container_ids)
        self.assertIn("still exist", str(ctx.exception))

    def test_a_resource_removed_meanwhile_is_accepted_and_the_others_returned(self):
        kept = self.daemon.add_container("geordi-dev-run-aaaaaaaaaaaa", labels("dev-run", LIVE), running=False)
        gone = "f" * 64  # listed earlier, removed before the inspect: not in a fresh listing either
        found = devrun._inspect(["container"], [kept, gone], devrun.all_container_ids)
        self.assertEqual([d["Id"] for d in found], [kept])

    def test_a_failing_listing_raises(self):
        self.daemon.hooks[("docker", "volume", "inspect")] = lambda cmd: _done(cmd, 1, b"", b"daemon error")
        self.daemon.hooks[("docker", "volume", "ls")] = lambda cmd: _done(cmd, 1, b"", b"daemon error")
        with self.assertRaises(devrun.DevrunError):
            devrun._inspect(["volume"], ["geordi-work-dddddddddddd"], lambda: devrun.project_volume_names("geordi"))

    def test_output_that_is_not_json_raises(self):
        self.daemon.hooks[("docker", "volume", "inspect")] = lambda cmd: _done(cmd, 1, b"garbage", b"")
        with self.assertRaises(devrun.DevrunError):
            devrun._inspect(["volume"], ["x"], lambda: set())


class StateDirEnv(unittest.TestCase):
    """A temporary devrun state directory in DEVRUN_STATE_DIR, and CI unset, for the test's length."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = pathlib.Path(self.tmp.name) / "state"
        for k, v in ((devrun.STATE_ENV, str(self.dir)), ("CI", None), (devrun.MAX_RUNS_ENV, None)):
            saved = os.environ.get(k)
            self.addCleanup(lambda k=k, saved=saved: os.environ.pop(k, None) if saved is None else os.environ.__setitem__(k, saved))
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        devrun.state_dir()
        self.daemon = FakeDaemon()
        self.daemon.install(self)


class GcKeepsRecords(StateDirEnv):
    def test_a_dead_runs_record_is_kept_when_the_final_inspect_fails(self):
        devrun.RunRecord(self.dir, DEAD, {"project": "geordi"}).finish(clean=False)
        self.daemon.add_container("geordi-dev-run-" + DEAD, labels("dev-run", DEAD), running=False)
        # The removal fails, and from then on Docker cannot inspect: the container still exists.
        def broken(cmd):
            self.daemon.hooks[("docker", "container", "inspect")] = lambda c: _done(c, 1, b"", b"daemon error")
            return _done(cmd, 1, b"", b"daemon error")
        self.daemon.hooks[("docker", "rm")] = broken
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = devrun.main(["--gc", "geordi"])
        self.assertNotEqual(code, 0)
        self.assertTrue((self.dir / "runs" / f"{DEAD}.lock").exists(), "gc forgot a dead run that still has a container")
        self.assertEqual(devrun.run_liveness(self.dir, DEAD), "dead")

    def test_a_dead_runs_record_is_forgotten_once_nothing_is_left(self):
        devrun.RunRecord(self.dir, DEAD, {"project": "geordi"}).finish(clean=False)
        self.daemon.add_container("geordi-dev-run-" + DEAD, labels("dev-run", DEAD), running=False)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(devrun.main(["--gc", "geordi"]), 0)
        self.assertFalse((self.dir / "runs" / f"{DEAD}.lock").exists())


# --------------------------------------------------------------------------- #
# Finding 2: containers that outlive their runner, and admission kept until the container is gone.
# --------------------------------------------------------------------------- #


def survivor(name="geordi-dev-run-dddddddddddd", phase="command", mounts=(), project="geordi", exclusive=False):
    return {"id": "x", "name": name, "project": project, "run_id": "dddddddddddd", "phase": phase,
            "timeout": "300", "started": "", "mounts": list(mounts), "exclusive": exclusive}


class SurvivorAdmission(GateCase):
    def contender(self, exclusive=False, max_runs=4, survivors=None):
        c = Contender(self.dir, exclusive, max_runs, survivors)
        self.contenders.append(c)
        return c

    def test_a_survivor_holds_a_slot(self):
        left = [survivor()]
        a = self.contender(max_runs=2, survivors=lambda: list(left))
        self.admitted(a)  # one slot for the survivor, one for a
        b = self.contender(max_runs=2, survivors=lambda: list(left))
        b.wait_attempts(3)
        self.assertFalse(b.admitted.is_set())
        self.assertTrue(any("geordi-dev-run-dddddddddddd" in m and "dead" in m for m in b.messages), b.messages)
        left.clear()
        self.admitted(b)

    def test_an_exclusive_survivor_keeps_every_ordinary_run_out(self):
        # Review of #13: a dead --exclusive runner's command still has the machine to itself.
        left = [survivor(exclusive=True)]
        b = self.contender(max_runs=4, survivors=lambda: list(left))
        b.wait_attempts(3)
        self.assertFalse(b.admitted.is_set())
        self.assertTrue(any("geordi-dev-run-dddddddddddd" in m and "exclusive" in m for m in b.messages), b.messages)
        left.clear()
        self.admitted(b)

    def test_survivors_of_other_phases_hold_no_slot(self):
        left = [survivor(phase="fetch"), survivor(phase="prep")]
        self.admitted(self.contender(max_runs=1, survivors=lambda: list(left)))

    def test_a_survivor_of_an_older_runner_without_a_phase_label_holds_a_slot(self):
        left = [survivor(phase=None)]
        b = self.contender(max_runs=1, survivors=lambda: list(left))
        b.wait_attempts(3)
        self.assertFalse(b.admitted.is_set())
        left.clear()
        self.admitted(b)

    def test_an_exclusive_run_waits_for_a_survivor_and_says_why(self):
        left = [survivor()]
        e = self.contender(exclusive=True, survivors=lambda: list(left))
        e.wait_attempts(3)
        self.assertFalse(e.admitted.is_set())
        self.assertTrue(any(m.startswith("devrun: waiting for exclusive access (the runner of geordi-dev-run-dddddddddddd is dead")
                            for m in e.messages), e.messages)
        # While it waits, new ordinary runs queue behind it.
        b = self.contender()
        b.wait_attempts(3)
        self.assertFalse(b.admitted.is_set())
        left.clear()
        self.admitted(e)
        e.release()
        self.admitted(b)

    def test_an_exclusive_run_waiting_for_a_survivor_gives_up_at_its_wait_limit(self):
        gate = devrun.Gate(self.dir, 1, clock=FakeClock(), sleep=lambda s: None, report=lambda m: None,
                           survivors=lambda: [survivor()])
        with self.assertRaises(devrun.DevrunError) as ctx:
            gate.admit(True, 0)
        self.assertIn("gave up", str(ctx.exception))
        self.try_once(exclusive=True).release()  # it released the turnstile and the gate

    def test_a_named_lock_waits_for_a_blocking_survivor(self):
        left = [survivor(mounts=["geordi-target-pinned-k"])]
        clock = FakeClock()
        polls = []
        gate = devrun.Gate(self.dir, 1, clock=clock, sleep=lambda s: (polls.append(s), left.clear() if len(polls) == 3 else None),
                           report=lambda m: None, survivors=lambda: list(left))
        with gate.hold("pinned-geordi-k.lock", "the pinned build target", None,
                       blocking=lambda s: "geordi-target-pinned-k" in s["mounts"]):
            self.assertEqual(len(polls), 3)
        # A survivor that does not mount it does not block.
        left.append(survivor(mounts=["other"]))
        gate.hold("pinned-geordi-k.lock", "the pinned build target", 0,
                  blocking=lambda s: "geordi-target-pinned-k" in s["mounts"]).release()


class SurvivorScan(StateDirEnv):
    def setUp(self):
        super().setUp()
        self.ids = {}

    def run_container(self, rid, state, running=True, owner="geordi", name=None, timeout="300",
                      started="2026-11-14T02:59:00.5Z", phase="command", admission=None, record_admission=None):
        """A dev-run container of a run whose record is 'alive' (held by a child), 'dead', or 'unknown'."""
        if state == "dead":
            facts = {"project": owner}
            if record_admission:
                facts["admission"] = record_admission
            devrun.RunRecord(self.dir, rid, facts).finish(clean=False)
        elif state == "alive":
            child = subprocess.Popen([sys.executable, "-c", HOLD_RECORD, str(ROOT / "bin" / "devrun"), str(self.dir), rid],
                                     stdout=subprocess.PIPE, stdin=subprocess.PIPE)
            self.assertEqual(child.stdout.readline(), b"recorded\n")
            def stop(child=child):
                child.kill()
                child.wait()
                child.stdin.close()
                child.stdout.close()
            self.addCleanup(stop)
        lab = labels("dev-run", rid, owner)
        if phase is not None:
            lab[devrun.PHASE_LABEL] = phase
        if timeout is not None:
            lab[devrun.TIMEOUT_LABEL] = timeout
        if admission is not None:
            lab[devrun.ADMISSION_LABEL] = admission
        name = name or devrun.run_resource_names(owner, rid)["container"]
        self.ids[rid] = self.daemon.add_container(name, lab, running=running, started=started)
        return name

    def test_only_running_containers_of_dead_runs_with_valid_labels_are_survivors(self):
        dead = self.run_container("d00000000001", "dead")
        self.run_container("a00000000001", "alive")
        self.run_container("e00000000001", "unknown")
        self.run_container("d00000000002", "dead", running=False)
        self.run_container("d00000000003", "dead", name="geordi-dev-run-d00000000009")  # name and label disagree
        self.daemon.add_container("geordi-dev-run", labels("dev-run"))  # no run id
        self.daemon.add_container("unrelated", {})
        found = devrun.Survivors(self.dir, report=lambda m: None)()
        self.assertEqual([s["name"] for s in found], [dead])
        self.assertEqual(found[0]["phase"], "command")

    def test_a_survivor_is_exclusive_by_its_label_or_by_its_record(self):
        self.run_container("d00000000001", "dead", admission="exclusive")
        self.run_container("d00000000002", "dead", admission=None, record_admission="exclusive")
        self.run_container("d00000000003", "dead", admission="ordinary")
        self.run_container("d00000000004", "dead", admission=None)
        found = {s["run_id"]: s["exclusive"] for s in devrun.Survivors(self.dir, report=lambda m: None)()}
        self.assertEqual(found, {"d00000000001": True, "d00000000002": True, "d00000000003": False, "d00000000004": False})

    def test_a_survivor_past_its_own_timeout_is_stopped_and_no_other_container(self):
        overdue = self.run_container("d00000000001", "dead", timeout="60", started="2026-11-14T02:58:59.9Z")
        within = self.run_container("d00000000002", "dead", timeout="60", started="2026-11-14T02:59:30Z")
        legacy = self.run_container("d00000000003", "dead", timeout=None, phase=None, started="2026-11-14T01:00:00Z")
        self.run_container("a00000000001", "alive", timeout="60", started="2026-11-14T01:00:00Z")
        self.run_container("e00000000001", "unknown", timeout="60", started="2026-11-14T01:00:00Z")
        messages = []
        found = devrun.Survivors(self.dir, report=messages.append)()
        self.assertEqual(sorted(s["name"] for s in found), sorted([within, legacy]))
        killed = [c[2] for c in self.daemon.calls if c[:2] == ["docker", "kill"]]
        self.assertEqual(killed, [self.ids["d00000000001"]])
        self.assertFalse(self.daemon.containers[overdue]["running"])
        self.assertEqual(messages, [f"devrun: stopping {overdue}: its runner is dead and its 60 s timeout has passed"])

    def test_gc_dry_run_stops_nothing(self):
        self.run_container("d00000000001", "dead", timeout="60", started="2026-11-14T01:00:00Z")
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(devrun.main(["--gc", "geordi", "--dry-run"]), 0)
        self.assertFalse(any(c[:2] in (["docker", "kill"], ["docker", "rm"]) for c in self.daemon.calls))
        self.assertIn("would stop container geordi-dev-run-d00000000001", out.getvalue())

    def test_gc_stops_an_overdue_survivor_and_then_removes_it(self):
        name = self.run_container("d00000000001", "dead", timeout="60", started="2026-11-14T01:00:00Z")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(devrun.main(["--gc", "geordi"]), 0)
        self.assertNotIn(name, self.daemon.containers)

    def test_gc_keeps_a_survivor_within_its_timeout(self):
        name = self.run_container("d00000000001", "dead", timeout="7200", started="2026-11-14T02:59:00Z")
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(devrun.main(["--gc", "geordi"]), 0)
        self.assertTrue(self.daemon.containers[name]["running"])
        self.assertIn("still running, within its timeout", out.getvalue())

    def test_docker_times_are_read_with_their_zone(self):
        self.assertEqual(devrun.parse_docker_time("2026-11-14T03:19:46Z"), 1794626386.0)
        self.assertAlmostEqual(devrun.parse_docker_time("2026-11-13T19:21:36.244827538-08:00"), 1794626496.244827538, places=5)
        with self.assertRaises(devrun.DevrunError):
            devrun.parse_docker_time("yesterday")


class HoldsUntilStopped(StateDirEnv):
    """The SIGTERM half of finding 2: locks handed to start() outlive a signal until the container is gone."""

    def setUp(self):
        super().setUp()
        self.gate = devrun.Gate(self.dir, 1)
        self.docker = devrun.Docker("geordi", RUN_ID, "img", "1", "1g")
        self.docker.create(["sleep", "100"], False, "geordi-target-x")

    def slot_free(self):
        try:
            self.gate.admit(False, 0).release()
            return True
        except devrun.DevrunError:
            return False

    def test_a_signal_during_the_command_keeps_the_slot_until_cleanup_removed_the_container(self):
        self.daemon.hooks[("docker", "start")] = interrupt
        with self.assertRaises(devrun.DevrunError):
            self.docker.start(60, [self.gate.admit(False, 0)])
        self.assertFalse(self.slot_free())
        self.assertTrue(self.docker.cleanup())
        self.assertTrue(self.slot_free())

    def test_a_container_still_running_after_start_returned_keeps_the_slot(self):
        def detached(cmd):
            return _done(cmd, 0)  # the client returned, the container did not stop
        self.daemon.containers[self.docker.name]["running"] = True
        self.daemon.hooks[("docker", "start")] = detached
        self.docker.start(60, [self.gate.admit(False, 0)])
        self.assertFalse(self.slot_free())
        self.docker.remove()
        self.assertTrue(self.slot_free())

    def test_a_container_that_cannot_be_removed_keeps_the_slot(self):
        self.daemon.hooks[("docker", "start")] = interrupt
        self.daemon.hooks[("docker", "rm")] = lambda cmd: _done(cmd, 1, b"", b"daemon error")
        with self.assertRaises(devrun.DevrunError):
            self.docker.start(60, [self.gate.admit(False, 0)])
        self.assertFalse(self.docker.cleanup())
        self.assertFalse(self.slot_free())
        self.docker.release_holds()  # what main_inner does after the record shows the run dead
        self.assertTrue(self.slot_free())

    def test_a_normal_end_releases_the_slot_once_docker_confirms_the_stop(self):
        self.docker.start(60, [self.gate.admit(False, 0)])
        self.assertTrue(self.slot_free())


class RunUnderSignal(StateDirEnv):
    """main() end to end against the fake daemon: what is held when cleanup removes the container."""

    def setUp(self):
        super().setUp()
        for sig in (devrun.signal.SIGTERM, devrun.signal.SIGINT):
            self.addCleanup(devrun.signal.signal, sig, devrun.signal.getsignal(sig))
        self.repo = pathlib.Path(self.tmp.name) / "repo"
        self.repo.mkdir()
        git = ["git", "-C", str(self.repo), "-c", "user.name=t", "-c", "user.email=t@invalid"]
        subprocess.run(git + ["init", "-q"], check=True)
        (self.repo / "x").write_text("x\n")
        subprocess.run(git + ["add", "x"], check=True)
        subprocess.run(git + ["commit", "-qm", "x"], check=True)
        self.key = devrun.source_key(os.path.realpath(str(self.repo)))
        self.out = pathlib.Path(self.tmp.name) / "out"

    def main(self, *mode):
        with contextlib.redirect_stderr(io.StringIO()) as err:
            code = devrun.main(["geordi", str(self.repo), *mode, "--max-runs", "1", "--wait", "0",
                                "--out", str(self.out), "--", "true"])
        return code, err.getvalue()

    def is_command(self, cmd):
        name = self.daemon.by_ref(cmd[-1])
        return name is not None and devrun.INNER_SCRIPT in self.daemon.containers[name].get("cmd", [])

    def lock_free(self, name):
        try:
            devrun.Gate(self.dir, 1).hold(name, name, 0).release()
            return True
        except devrun.DevrunError:
            return False

    def test_sigterm_during_the_command_keeps_admission_until_the_container_is_removed(self):
        seen = {}

        def start(cmd):
            if self.is_command(cmd):
                self.daemon.containers[self.daemon.by_ref(cmd[-1])]["running"] = True
                interrupt()

        def rm(cmd):
            if self.is_command(cmd):
                try:
                    devrun.Gate(self.dir, 1).admit(True, 0).release()
                    seen["exclusive admitted while the container existed"] = True
                except devrun.DevrunError:
                    seen["exclusive admitted while the container existed"] = False
        self.daemon.hooks[("docker", "start")] = start
        self.daemon.hooks[("docker", "rm")] = rm
        code, err = self.main("--worktree")
        self.assertEqual(code, 2, err)
        self.assertIn("interrupted by signal 15", err)
        self.assertEqual(seen, {"exclusive admitted while the container existed": False})
        self.assertEqual(self.daemon.containers, {})
        devrun.Gate(self.dir, 1).admit(True, 0).release()  # and released after it

    def test_the_admission_mode_is_on_the_command_container_and_in_the_record(self):
        seen = []

        def start(cmd):
            if self.is_command(cmd):
                c = self.daemon.containers[self.daemon.by_ref(cmd[-1])]
                rid = c["labels"][devrun.RUN_ID_LABEL]
                record = json.loads((self.dir / "runs" / f"{rid}.lock").read_text())
                seen.append((c["labels"].get(devrun.ADMISSION_LABEL), record.get("admission")))
        self.daemon.hooks[("docker", "start")] = start
        for mode in (["--worktree", "--exclusive"], ["--worktree"]):
            code, err = self.main(*mode)
            self.assertEqual(code, 0, err)
            self.out.rmdir()
        self.assertEqual(seen, [("exclusive", "exclusive"), ("ordinary", "ordinary")])

    def test_a_pinned_run_holds_its_targets_lock_while_the_command_runs_and_a_worktree_run_does_not(self):
        lock = f"pinned-geordi-{self.key}.lock"
        held = []
        mounts = []

        def start(cmd):
            if self.is_command(cmd):
                held.append(not self.lock_free(lock))
                mounts.append(self.daemon.containers[self.daemon.by_ref(cmd[-1])]["mounts"])
        self.daemon.hooks[("docker", "start")] = start
        for mode in (["--commit", "HEAD"], ["--worktree"]):
            code, err = self.main(*mode)
            self.assertEqual(code, 0, err)
            self.out.rmdir()
        self.assertEqual(held, [True, False])
        self.assertIn(f"geordi-target-pinned-{self.key}", mounts[0])
        self.assertIn(f"geordi-target-{self.key}", mounts[1])
        self.assertTrue(self.lock_free(lock))
        self.assertEqual(self.daemon.volumes[f"geordi-target-pinned-{self.key}"][devrun.ROLE_LABEL], "target-pinned")


if __name__ == "__main__":
    unittest.main()
