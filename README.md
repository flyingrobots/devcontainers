# devcontainers

Shared development containers for the flyingrobots Rust repositories
(Geordi, Bunny, Echo, ninelives). Builds, tests, and toolchains run inside these
containers, never on the host.

- One base image per Rust toolchain, pinned to the version in each repository's
  `rust-toolchain.toml`.
- One guarded runner that every repository calls. The runner claims `git-locks`
  keys, applies a timeout and resource limits, mounts only named volumes (never
  a host path), and audits Docker for litter before and after each run.

The rules are in [`docs/hygiene.md`](docs/hygiene.md). Work is tracked in GitHub
Issues with `issue-dag/2` frontmatter.

## Build and test the base image

```sh
scripts/build-image 1.96.0   # builds flyingrobots/rust-dev:1.96.0 under the git-locks keys
tests/smoke-image 1.96.0     # checks it in offline, read-only, unprivileged containers
```

Pinned base digests live in `images/rust-dev/base-digests`, one line per Rust
version. The image runs as UID 10001. Mount points for the named volumes:
`/work` (the copy), `/scratch` (inputs, logs, exports), `/target` (build output),
`/usr/local/cargo/registry`, and `/usr/local/cargo/git` (cargo caches).

## Run a repository's gates: `bin/devrun`

`bin/devrun` (Python 3.9+, standard library only) copies a repository into
locked-down containers and runs one command there. Nothing is mounted from the
host; every rule it enforces is in [`docs/hygiene.md`](docs/hygiene.md).

```sh
# A pinned commit, fetching dependencies first (network only for cargo fetch):
bin/devrun bunny ~/git/bunny --commit HEAD --fetch -- cargo test --locked --workspace

# Gates that read commit history (Bunny's repo-respect):
bin/devrun bunny ~/git/bunny --history origin/main..HEAD -- cargo run --locked -p xtask -- repo-respect check

# Iterate on uncommitted work (marked unpinned), exporting a file and a patch:
bin/devrun ninelives ~/git/ninelives --worktree --export report.txt --export-patch -- cargo update
```

- Source modes: `--commit SHA` (pinned; required for merge-gate evidence),
  `--history BASE..HEAD`, `--worktree` (unpinned). The host builds and checks
  the tarball before Docker sees it: no `.git`, no absolute or escaping
  symlinks, no hard links, no setuid or setgid bits, no special files; every
  owner becomes UID 10001.
- Phase 1 (`--fetch`) runs `cargo fetch --locked` with the network and writable
  cargo caches, from a copy without `.cargo/config*` or `rust-toolchain*`, with
  the compiler pinned and the wrappers cleared. Phase 2 runs the command from a
  fresh copy at `/work`, with `--network none` unless `--network` is given.
- Outputs leave only through `--export PATH` (files written under
  `/scratch/out/` in the container) and `--export-patch` (a patch from the
  throwaway repository), into a fresh folder outside every repository
  (`--out DIR`, or a new temporary folder).
- Each run holds the git-locks keys `host/heavy-work` and
  `host/docker/<project>-dev-run/`, and removes only the container it created.
  `--timeout` (default 1800 s) is shorter than the lease.
- Not yet: the Docker litter audit, run receipts, free-space and volume budget
  checks (flyingrobots/devcontainers#5).

Test it:

```sh
bin/devrun devcontainers . --worktree -- python3 -m unittest discover -s tests   # unit tests, in a container
tests/integration-devrun                                                            # real Docker
```
