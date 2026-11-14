# devcontainers

Shared development containers for the flyingrobots Rust repositories
(Geordi, Bunny, Echo, ninelives). Builds, tests, and toolchains run inside these
containers, never on the host.

- One base image per Rust toolchain, pinned to the version in each repository's
  `rust-toolchain.toml`.
- One guarded runner that every repository calls. The runner applies a timeout
  and resource limits, mounts only named volumes (never a host path), gives each
  run its own container and volumes, and lets several runs work at once under a
  small cap.

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
- `--timeout` (default 1800 s) bounds each phase's command.
- Not yet: the Docker litter audit, run receipts, free-space and volume budget
  checks (flyingrobots/devcontainers#5).

### Concurrent runs

Runs do not wait for each other unless the machine is full. The rules are in
[`docs/hygiene.md`](docs/hygiene.md) sections 5 and 10.

- Each run gets a run id and its own container (`<project>-dev-run-<id>`), copy
  volume, and scratch volume, labelled with the run id, and removes them on
  every exit path, including SIGTERM and SIGINT.
- At most 4 command phases run at once on the machine. `--max-runs N` or
  `DEVRUN_MAX_RUNS=N` sets the cap; a waiting run prints how long it has waited,
  and gives up after `--wait SECONDS` (default 3600). A run keeps its slot until
  its container has stopped.
- A command container whose runner was killed (SIGKILL) keeps counting against
  the cap, and `--exclusive` runs wait for it, until it ends. Once its own
  `--timeout` has passed, the next run that waits for it (or `--gc`) stops it;
  nothing stops it earlier.
- `--exclusive` waits until no other command phase runs and keeps them all out
  until it finishes. Use it for every performance measurement:
  `bin/devrun echo ~/git/echo --commit HEAD --exclusive -- cargo bench --locked`.
- Fetch phases of one project take turns (cargo's own cache lock cannot work on
  the read-only root).
- `--commit` and `--history` runs of one worktree take turns on that worktree's
  pinned build target (below).
- With `CI=true` none of this coordination applies; CI machines run one job.
- Runs register `host/docker/<project>-dev-run-<id>/` in the workstation
  git-locks store for visibility; without git-locks they run unregistered.

### Build output and disk

Build output lives in kept volumes per worktree, keyed by a hash of the
worktree's real path: `<project>-target-<key>` for `--worktree` runs and
`<project>-target-pinned-<key>` for `--commit` and `--history` runs. Each
worktree keeps its own warm caches and never sees another worktree's artifacts.
Two `--worktree` runs from the same worktree share their target safely: cargo
locks its build directory. The cost is disk: each target can grow to a full
build of the workspace, so eight worktrees of a large workspace can hold several
times the 20 GiB per-project budget. `--evidence` builds into a new, empty volume
that belongs to the one run and is removed with it.

A pinned run's result does not depend on what else runs: its copy gets the
current time (`--commit`) or is checked out in the container (`--history`), and
no other run can build in the pinned target until its command has ended, so
cargo rebuilds the workspace's crates from this run's source and reuses only
registry and git dependencies. Pinned runs of one worktree therefore run their
commands one at a time. `--worktree` runs keep the files' own times, like cargo
on the host, and never see a pinned run's output; a tool that restores old
modification times can still make them reuse stale output
(flyingrobots/devcontainers#9).

### Leftovers: `bin/devrun --gc`

```sh
bin/devrun --gc bunny --dry-run   # list what would be removed
bin/devrun --gc bunny             # remove it
```

`--gc` removes the stopped containers and the volumes of runs that died without
cleaning up (killed with SIGKILL, or a crash), and the targets of worktrees that
no longer exist. A run counts as dead only when its liveness lock in the devrun
state directory is free, which proves its process exited. A dead run's container
that is still running is stopped first if its own timeout has passed, and kept
otherwise. `--gc` never removes a running container, a volume in use, the cargo
caches, or anything without a valid run id or source label, such as the
fixed-name volumes of older runner versions (remove those by hand once nothing
uses them). If Docker cannot inspect a resource that still exists, `--gc` stops
with an error and forgets no run.

Test it:

```sh
bin/devrun devcontainers . --worktree -- python3 -m unittest discover -s tests   # unit tests, in a container
tests/integration-devrun                                                            # real Docker, on the host
```
