# Docker hygiene rules (ULTRAMAX PARANOIA)

Threat model: every build script, dependency, test, and agent inside a container
is hostile. The host, its git repositories, its credentials, and other projects'
Docker resources must stay unreachable and unchanged. The runner (`bin/devrun`)
enforces every rule here; a rule that only lives in this file is not enforced.

## 1. Source isolation

- **Copy in, never mount.** No host path is bind-mounted into a container: not
  the repository, not `~/.cargo`, not `~/.ssh`, not the Docker socket.
- **Two copy modes:**
  - `--commit <sha>` (default, and required for merge-gate evidence):
    `git archive <sha>` on the host, streamed into the container. The copy is
    exact and pinned. No `.git` is ever copied.
  - `--worktree` (iteration only, marked *unpinned* in the receipt):
    `git ls-files -z --cached --others --exclude-standard
    --recurse-submodules`, streamed with `tar`. This includes new files that are
    not yet staged and excludes ignored files.
- **Copy checks, before any command runs** (the run fails on any finding):
  - no `.git` file or directory anywhere in the copy;
  - no symlink with an absolute target or a target outside the copy;
  - no setuid or setgid bit, no device file, no named pipe;
  - the SHA-256 of the streamed tarball is recorded in the receipt.
- **Git for tools that need it.** Some gates read git state (Bunny's
  `repo-respect`, Geordi's `git ls-files` checks). Inside the container, the
  runner creates a throwaway repository: `git init`, commit the base tree, then
  stage the head tree. It is never a copy of a real `.git`.

## 2. Container privileges

- Non-root user with a fixed UID (`10001`), `--user 10001:10001`.
- `--cap-drop ALL`, `--security-opt no-new-privileges`.
- `--read-only` root filesystem. Writable places: `/work` (the copy, in a tmpfs
  or the scratch volume), `/tmp` (tmpfs with a size limit), and the named
  volumes in section 5.
- Limits on every run: `--pids-limit`, `--memory` with `--memory-swap` equal to
  it, `--cpus`, `--ulimit nofile`.
- Never `--privileged`, `--network host`, `--pid host`, `--ipc host`, or added
  devices.
- Clean environment: no host variables pass through. No tokens, no `GH_TOKEN`,
  no SSH agent. `HOME` is inside the container.

## 3. Network

- **Phase 1, fetch:** `cargo fetch --locked` with network access, writing only
  to the project's registry volume.
- **Phase 2, build and test:** `--network none` and `CARGO_NET_OFFLINE=true`. A
  build script cannot download or send anything.
- A command that truly needs the network in phase 2 must say so with
  `--network`, and the receipt records it.
- The runner never creates a Docker network. No Docker Compose.

## 4. Supply chain

- Base images are pinned by digest (`rust@sha256:…`), not by tag. The digest is
  in the receipt.
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
| Run container | `<project>-dev-run` (one at a time, under a lock) | `dev-run` |
| Cargo registry cache | `<project>-cargo-registry` (per project: no cross-project cache poisoning) | `cargo-registry` |
| Build output, iteration | `<project>-target` | `target` |
| Build output, evidence | `<project>-target-evidence`, emptied before each merge-gate run | `target-evidence` |
| Logs, test data, exports | `<project>-scratch` | `scratch` |

- No anonymous volumes. Images must not declare `VOLUME`.
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

- Each run claims `host/heavy-work` and `host/docker/<project>-dev/` in the
  workstation `git-locks` store, with a lease longer than the timeout.

## 11. Not ours

Resources without the `org.flyingrobots.owner` label belong to other projects.
The tools never stop, remove, or prune them.
