# Docker hygiene rules (ULTRAMAX PARANOIA)

Threat model: every build script, dependency, test, and agent inside a container
is hostile. The host, its git repositories, its credentials, and other projects'
Docker resources must stay unreachable and unchanged. The runner (`bin/devrun`)
enforces every rule here; a rule that only lives in this file is not enforced.

**Status:** `bin/devrun` is not merged yet (flyingrobots/devcontainers#3). Until
it is, the rules about runs (copy-in, network phases, run-phase mounts, prep,
outputs, audit) are its specification, and nothing enforces them.
`scripts/build-image` and `tests/smoke-image` enforce the rules that apply to an
image build and a smoke test.

## 1. Source isolation

- **Copy in, never mount.** No host path is bind-mounted into a container: not
  the repository, not `~/.cargo`, not `~/.ssh`, not the Docker socket.
- **Two copy modes:**
  - `--commit <sha>` (default, and required for merge-gate evidence):
    `git archive <sha>` on the host, streamed into the container. The copy is
    exact and pinned. No `.git` is ever copied.
  - `--history <base>..<head>` (for gates that read commit history, such as
    Bunny's `repo-respect`): `git bundle create` on the host packs an existing
    ref that contains `<head>` (and one that contains `<base>` when it is not an
    ancestor). A bundle must carry the full ancestry to be cloneable, so it holds
    more than `<base>..<head>`; it is still an object export, never the original
    `.git`, and the runner never creates refs in the source repository. Inside the
    container, the runner fetches the bundle into a brand-new repository, pins
    `main` to `<head>` and `refs/remotes/origin/main` to `<base>`, and deletes the
    temporary refs. It checks that `HEAD` equals `<head>`. The `<head>` tree must
    also pass the archive checks on the host.
  - `--worktree` (iteration only, marked *unpinned* in the receipt):
    `git ls-files -z --cached --others --exclude-standard
    --recurse-submodules`, streamed with `tar`. This includes new files that are
    not yet staged and excludes ignored files.
- **Copy checks, before any command runs** (the run fails on any finding):
  - no `.git` file or directory anywhere in the copy;
  - no symlink with an absolute target or a target outside the copy;
  - no setuid or setgid bit, no device file, no named pipe;
  - the SHA-256 of the streamed tarball is recorded in the receipt.
- **Git for tools that need it.** Gates that only list files (Geordi's
  `git ls-files` checks, Bunny's `code-dojo --all`) get a throwaway repository:
  `git init` in the copy, with nothing copied from a real `.git`. Gates that read
  branch history or commit messages (Bunny's `repo-respect`) use `--history`.
- **The only `.git` in a container is one the runner created inside it:** an
  empty `git init` or a clone from a bundle. The copy check runs before that
  step, so a `.git` that arrived with the source always fails the run.

## 2. Container privileges

- Non-root user with a fixed UID (`10001`), `--user 10001:10001`.
- `--cap-drop ALL`, `--security-opt no-new-privileges`.
- `--read-only` root filesystem. Writable places: `/work` (the copy, at the
  root of the work volume), `/scratch` (which also holds `TMPDIR`, `/scratch/tmp`,
  because Docker mounts the `/tmp` tmpfs `noexec`), `/tmp` (tmpfs with a size limit), the
  other named volumes in section 5, and Docker's own `/dev/shm` and
  `/dev/mqueue`.
- **No writable directory above the copy.** Cargo reads `.cargo/config.toml` in
  the working directory and in every parent directory. The copy is the root of
  its own volume, so its only parent is the read-only root. Before each copy-in,
  the runner empties the work and scratch volumes completely, hidden entries
  included, so a `.cargo/config.toml` that one run leaves behind never reaches
  the next.
- `CARGO_HOME` is the image path `/usr/local/cargo`. It is read-only only
  because the run uses `--read-only`: the base image leaves it and the toolchain
  world-writable. Under `--read-only`, a run cannot plant a cargo `config.toml`
  or a `credentials.toml` there.
- No `RUSTUP_TOOLCHAIN` in the image or the run: a repository's
  `rust-toolchain.toml` channel must match the image. Otherwise rustup tries to
  install the other toolchain, and that fails on the read-only root. This
  catches an honest version mismatch only. A hostile repository can still run
  its own compiler, for example through a `path` toolchain or `build.rustc` in
  its own `.cargo/config.toml`, so a run's output never proves which compiler
  built it. The isolation rules contain such a compiler like any other code.
- Limits on every run: `--pids-limit`, `--memory` with `--memory-swap` equal to
  it, `--cpus`, `--ulimit nofile`.
- Never `--privileged`, `--network host`, `--pid host`, `--ipc host`, or added
  devices.
- Clean environment: no host variables pass through. No tokens, no `GH_TOKEN`,
  no SSH agent. `HOME` is inside the container.

## 3. Network

- **Phase 1, fetch:** `cargo fetch --locked` with network access and the cargo
  caches writable. It must run no code that the repository chooses, because a
  program that runs now can rewrite cached sources for every later run.
  `cargo fetch` asks the compiler for target information, so a repository's
  `build.rustc-wrapper`, `build.rustc`, or `path` toolchain would run here.
  Therefore:
  - The fetch copy contains no `.cargo/config` or `.cargo/config.toml` file
    and no `rust-toolchain` or `rust-toolchain.toml` file.
  - The fetch command runs with `RUSTUP_TOOLCHAIN` set to the image's version,
    `RUSTC=/usr/local/cargo/bin/rustc`, and `RUSTC_WRAPPER` and
    `RUSTC_WORKSPACE_WRAPPER` set empty. These override the same settings in
    any configuration file.
  - `cargo fetch` runs no build scripts and no procedural macros.
- **Phase 2, build and test:** `--network none` and `CARGO_NET_OFFLINE=true`. A
  build script cannot download or send anything.
- A command that truly needs the network in phase 2 must say so with
  `--network`, and the receipt records it.
- The runner never creates a Docker network. No Docker Compose.

## 4. Supply chain

- Base images are pinned by digest (`rust@sha256:…`), not by tag. The digest is
  in the receipt.
- Known gap: `clippy`, `rustfmt`, and the `wasm32-unknown-unknown` standard
  library come from the rustup server at image build time. rustup checks each
  file against the channel manifest for that exact version, but the manifest
  itself is not pinned here. `cargo-deny` is pinned by SHA-256.
- Every cargo command uses `--locked`. A changed `Cargo.lock` leaves the
  container only through an explicit patch export.
- Images build with the default builder. No new `buildx` builder. A new image is
  built only for a new toolchain version.

## 5. Names, labels, and volumes

Every resource has a fixed name and the labels `org.flyingrobots.owner=<project>`
and `org.flyingrobots.role=<role>`. Cleanup selects by these labels only.

| Resource | Name | Role label |
| --- | --- | --- |
| Base image | `flyingrobots/rust-dev:<rust-version>` | `base-image` |
| Upstream base, the build input | `rust@sha256:<digest>` from `images/rust-dev/base-digests`, pulled by digest. It carries only upstream labels. Keep it while its digest line exists; after removing the line, remove it with `docker image rm`. | none (upstream image) |
| Run container | `<project>-dev-run` (one at a time, under a lock) | `dev-run` |
| Cargo registry cache, at `/usr/local/cargo/registry` | `<project>-cargo-registry` (per project: no cross-project cache poisoning) | `cargo-registry` |
| Cargo git cache, at `/usr/local/cargo/git` | `<project>-cargo-git` | `cargo-git` |
| Build output, iteration | `<project>-target` | `target` |
| Build output, evidence | `<project>-target-evidence`, emptied before each merge-gate run | `target-evidence` |
| The copy, at `/work` | `<project>-work`, emptied before each copy-in | `work` |
| Inputs, logs, test data, exports, at `/scratch` | `<project>-scratch`, emptied before each copy-in | `scratch` |

- No anonymous volumes. Images must not declare `VOLUME`.
- The cargo caches are writable only in the fetch phase, which runs no code
  that the repository chooses (section 3). The build phase mounts them
  read-only, so a hostile build script cannot poison the cache for a later run.
- **Evidence runs use a fresh target.** A merge-gate run never reuses build
  output, so a stale cache cannot fabricate a passing result.

## 6. Outputs

- Only declared outputs leave the container: an artifacts folder and a patch
  generated from the throwaway repository.
- Exports go to a fresh, empty host folder outside every repository.
- Exported files must be regular files. Symlinks and special files are refused.
- Applying a patch to a real repository is always a separate host-side
  `git apply`, run on purpose and reviewed.

## 7. Lifecycle

- Each run is `docker create`, copy in, `docker start -a`, export, `docker rm`.
- A cleanup trap removes the container on success, failure, timeout, and
  signals.
- The command runs under a timeout that is shorter than the `git-locks` lease.

## 8. Budgets and free space

- Build output: at most 20 GiB per project. Logs and test data: at most 4 GiB,
  including at most 128 MiB of logs.
- The runner measures the volumes after each run and fails above a budget.
  Named volumes do not enforce size, so the measurement is the guard.
- The run does not start when the host or the Docker VM has less than 50 GiB
  free.

## 9. Audit and receipts

- Before and after each run, the runner lists containers, volumes, networks, and
  images. The run fails when Docker has any new resource that is not named and
  labeled per section 5, or when the run container still exists.
- Every run writes a receipt: image digest, copy mode, source SHA, tarball
  SHA-256, command, network mode, limits, exit code, duration, audit result, and
  volume sizes.

## 10. Locks

- Each run claims `host/heavy-work` and `host/docker/<project>-dev-run/` in the
  workstation `git-locks` store, with a lease longer than the timeout. The
  second key follows the workstation registry rule
  `host/docker/<exact-container-name>/`.

## 11. Not ours

Resources without the `org.flyingrobots.owner` label belong to other projects.
The tools never stop, remove, or prune them.
