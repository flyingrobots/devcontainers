"""Unit tests for bin/devrun: the host-side tarball checks and argument handling.

Run: python3 -m unittest discover -s tests
These tests need no Docker.
"""
import importlib.machinery
import importlib.util
import io
import pathlib
import tarfile
import tempfile
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


class ContainerOwnership(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.original_run = devrun.run
        devrun.run = lambda cmd, **kw: self.calls.append(cmd) or devrun.subprocess.CompletedProcess(cmd, 0, b"", b"")

    def tearDown(self):
        devrun.run = self.original_run

    def test_remove_skips_a_container_this_run_did_not_create(self):
        docker = devrun.Docker("geordi", "img", "1", "1g", False)
        docker.remove()
        self.assertEqual(self.calls, [])

    def test_remove_runs_once_after_create(self):
        docker = devrun.Docker("geordi", "img", "1", "1g", False)
        docker.create(["true"], False, "geordi-target")
        docker.remove()
        docker.remove()
        self.assertEqual([c for c in self.calls if c[:2] == ["docker", "rm"]], [["docker", "rm", "-f", "geordi-dev-run"]])

    def test_run_container_mounts_the_copy_at_work_with_home_set(self):
        docker = devrun.Docker("geordi", "img", "1", "1g", False)
        docker.create(["true"], False, "geordi-target")
        create = self.calls[-1]
        self.assertIn("type=volume,src=geordi-work,dst=/work", create)
        self.assertIn("HOME=/tmp/home", create)
        self.assertIn("TMPDIR=/exec-tmp", create)
        self.assertIn("/exec-tmp:rw,nosuid,nodev,exec,size=1g,mode=1777", create)
        self.assertEqual(create[create.index("--workdir") + 1], "/work")


class Locks(unittest.TestCase):
    def test_lock_keys_follow_the_container_name(self):
        captured = {}
        original = devrun.subprocess.call
        devrun.subprocess.call = lambda cmd, env=None: captured.setdefault("cmd", cmd) and 0
        try:
            env = dict(devrun.os.environ)
            env.pop("CI", None)
            env.pop(devrun.LOCK_ENV, None)
            saved = dict(devrun.os.environ)
            devrun.os.environ.clear()
            devrun.os.environ.update(env)
            devrun.main(["geordi", ".", "--commit", "HEAD", "--", "true"])
        finally:
            devrun.subprocess.call = original
            devrun.os.environ.clear()
            devrun.os.environ.update(saved)
        self.assertIn("host/heavy-work", captured["cmd"])
        self.assertIn("host/docker/geordi-dev-run/", captured["cmd"])


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

    def test_good_arguments(self):
        ns = devrun.parse_args(["geordi", ".", "--commit", "HEAD", "--fetch", "--export", "hashes.txt", "--", "cargo", "test"])
        self.assertEqual(ns.command, ["cargo", "test"])
        self.assertTrue(ns.fetch)


if __name__ == "__main__":
    unittest.main()
