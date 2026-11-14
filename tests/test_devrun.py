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
                                  "org.flyingrobots.run-id=0123456789ab"})

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

    def __init__(self, directory, exclusive, max_runs=4):
        self.clock = FakeClock()
        self.attempts = 0
        self.changed = threading.Condition()
        self.admitted = threading.Event()
        self.let_go = threading.Event()
        self.done = threading.Event()
        self.error = None
        self.gate = devrun.Gate(directory, max_runs, clock=self.clock, sleep=self.clock.sleep,
                                report=self._report, poll=0.5, report_every=0.5)
        self.thread = threading.Thread(target=self._run, args=(exclusive,), daemon=True)
        self.thread.start()

    def _report(self, _msg):
        with self.changed:
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


def target(path, key=None, name=None):
    key = key or devrun.source_key(path)
    return {"name": name or devrun.target_volume_name("geordi", key),
            "labels": labels("target", **{devrun.SOURCE_PATH_LABEL: path, devrun.SOURCE_KEY_LABEL: key})}


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


if __name__ == "__main__":
    unittest.main()
