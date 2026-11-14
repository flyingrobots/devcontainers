# Docker hygiene rules (ULTRAMAX PARANOIA)

Threat model: every build script, dependency, test, and agent inside a container
is hostile. The host, its git repositories, its credentials, and other projects'
Docker resources must stay unreachable and unchanged. The runner (`bin/devrun`)
enforces every rule here; a rule that only lives in this file is not enforced.

**Status:** `bin/devrun` enforces the rules about runs (copy-in, network
phases, run-phase mounts, prep, outputs, names, concurrency). The litter audit,
the receipts, and the budget checks (sections 8 and 9) are not implemented yet
(flyingrobots/devcontainers#5): until they are, those sections are a
specification. `scripts/build-image` and `tests/smoke-image` enforce the rules
that apply to an image build and a smoke test.

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
  root of the work volume), `/scratch`, `/tmp` (tmpfs with a size limit, `noexec`),
  `/exec-tmp` (`TMPDIR`: an `exec` tmpfs, also 1 GiB, so test binaries such as doctests
  can run), the
  other named volumes in section 5, and Docker's own `/dev/shm` and
  `/dev/mqueue`.
- **No writable directory above the copy.** Cargo reads `.cargo/config.toml` in
  the working directory and in every parent directory. The copy is the root of
  its own volume, so its only parent is the read-only root. Each run creates its
  own work and scratch volumes, new and empty, and removes them at the end, so a
  `.cargo/config.toml` that one run leaves behind never reaches another run.
  Before each copy-in (the fetch copy, then the command copy) the runner also
  empties both volumes completely, hidden entries included, so nothing the fetch
  phase leaves reaches the command phase.
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

Every resource has a name built from the project (and, for one run's own
resources, the run id) and the labels `org.flyingrobots.owner=<project>` and
`org.flyingrobots.role=<role>`. A run's own container and volumes also carry
`org.flyingrobots.run-id=<run-id>`, so cleanup can prove which run created
them. Cleanup selects by these labels only, and a name must match its labels.

A run id is 12 hexadecimal digits from a random UUID, new for every run. A
source key is the first 16 hexadecimal digits of the SHA-256 of the real path
of the repository's top-level directory (`git rev-parse --show-toplevel`,
symlinks resolved), so each git worktree has its own key.

| Resource | Name | Role label | Lifetime |
| --- | --- | --- | --- |
| Base image | `flyingrobots/rust-dev:<rust-version>` | `base-image` | Until a new toolchain replaces it |
| Upstream base, the build input | `rust@sha256:<digest>` from `images/rust-dev/base-digests`, pulled by digest. It carries only upstream labels. Keep it while its digest line exists; after removing the line, remove it with `docker image rm`. | none (upstream image) | As left |
| Run container | `<project>-dev-run-<run-id>`, also labelled with the run id, `org.flyingrobots.phase=<prep\|copy\|fetch\|command>`, and `org.flyingrobots.timeout=<seconds>` (section 10 uses both when its runner has died) | `dev-run` | One run; removed by the run |
| Cargo registry cache, at `/usr/local/cargo/registry` | `<project>-cargo-registry` (per project: no cross-project cache poisoning) | `cargo-registry` | Kept |
| Cargo git cache, at `/usr/local/cargo/git` | `<project>-cargo-git` | `cargo-git` | Kept |
| Build output, `--worktree` runs | `<project>-target-<source-key>`, also labelled `org.flyingrobots.source-path=<real path>` and `org.flyingrobots.source-key=<source-key>` (one per worktree) | `target` | Kept; `devrun --gc` removes it once the worktree path no longer exists |
| Build output, pinned runs (`--commit`, `--history`) | `<project>-target-pinned-<source-key>`, with the same source labels (one per worktree) | `target-pinned` | Kept; `devrun --gc` removes it once the worktree path no longer exists |
| Build output, evidence | `<project>-target-evidence-<run-id>`, new and empty for each `--evidence` run, also labelled with the run id | `target-evidence` | One run; removed by the run |
| The copy, at `/work` | `<project>-work-<run-id>`, also labelled with the run id | `work` | One run; removed by the run |
| Inputs, logs, test data, exports, at `/scratch` | `<project>-scratch-<run-id>`, also labelled with the run id | `scratch` | One run; removed by the run |

- No anonymous volumes. Images must not declare `VOLUME`.
- The cargo caches are writable only in the fetch phase, which runs no code
  that the repository chooses (section 3). The build phase mounts them
  read-only, so a hostile build script cannot poison the cache for a later run.
- **Evidence runs use a fresh target.** A merge-gate run never reuses build
  output, so a stale cache cannot fabricate a passing result. The evidence target
  belongs to the one run, so concurrent evidence runs never share one.
- **What a pinned run guarantees about its build.** A `--commit` or `--history`
  run without `--evidence` builds into its worktree's pinned target, which
  `--worktree` runs never use. It takes that target's lock (section 10) before its
  command container starts and keeps it until the container has stopped. Inside
  the container the copy gets the current time (`--commit`) or is checked out
  then (`--history`), so every source file is newer than any build output already
  in the target: cargo rebuilds the workspace's own crates from this run's copy
  and reuses only registry and git dependencies, which it identifies by version
  and checksum rather than by time. No other run can write the target between the
  time refresh and the end of the command, so the result does not depend on what
  else runs. Limits: the command itself can still change the copy before it
  builds, a build script can leave files in the target that a later pinned run
  reads (the target is still not evidence), and with `CI=true` there is no lock,
  which is safe only because a CI machine runs one job. The cost is a second
  target per worktree that runs both modes, and pinned runs of one worktree run
  their command phases one at a time; runs from different worktrees, and
  `--worktree` runs, are not delayed.
- A run refuses a shared volume (a cache or a target) that exists with other
  labels: another owner, another role, or, for a target, another source path or
  key. It refuses a per-run volume or a container that already exists under its
  name.
- Fixed-name volumes from earlier versions of the runner (`<project>-work`,
  `<project>-scratch`, `<project>-target`, `<project>-target-evidence`) are no
  longer used. They have no run id or source label, so `devrun --gc` never
  removes them; remove them by hand with `docker volume rm` once no older runner
  uses them.

### What concurrent runs share

Runs of different projects share nothing but the image. Concurrent runs of one
project share only these, and each sharing has a reason:

- **The cargo caches**, read-only for every command phase. Only a fetch phase
  writes them, and fetch phases of one project take turns (section 10), so
  there is never more than one writer. A command phase can read the caches while
  another run's fetch phase adds to them. Cargo writes a crate's sources into a
  new directory and marks it complete last; a reader that needs a crate it did
  not fetch itself finds it missing or incomplete and fails, because it cannot
  write. This is cargo's design and is not tested here. The writer still runs no
  repository-chosen code, so the poisoning rule above holds as before; what is
  new is only that a read and a write can happen at the same moment.
- **The `--worktree` target of one worktree**, read-write, when two
  `--worktree` runs come from the same worktree at once. Cargo's build-directory
  lock (`.cargo-lock` in the target, a file lock that works across containers on
  one Docker volume) serializes cargo's own builds in it; cargo prints "Blocking
  waiting for file lock on build directory". A command that writes `/target`
  without cargo is not serialized. One run's build scripts can change what the
  other run builds from, which was already true of consecutive runs: the
  iteration target is never evidence. `--worktree` runs keep the files' own
  times, so if a file is edited between the copies of two such runs, the run with
  the older copy can reuse the other's build of the newer content; the same is
  true of cargo on the host.
- **The pinned target of one worktree**, never at the same time: pinned runs of
  one worktree take turns on its lock for their whole command phase (above).
  Runs from different worktrees never share a target.

## 6. Outputs

- Only declared outputs leave the container: an artifacts folder and a patch
  generated from the throwaway repository.
- Exports go to a fresh, empty host folder outside every repository.
- Exported files must be regular files. Symlinks and special files are refused.
- Applying a patch to a real repository is always a separate host-side
  `git apply`, run on purpose and reviewed.

## 7. Lifecycle

- Each run creates its volumes, then for each phase does `docker create`, copy
  in, `docker start -a`, export, `docker rm`, and finally removes its volumes.
- Cleanup removes the container and the per-run volumes on success, failure,
  timeout, and SIGTERM or SIGINT. After the first signal, further signals are
  ignored, so they cannot cut cleanup short. Cleanup removes only what this run
  created; the run's own records say what that is.
- A run records that a container or volume may exist before it asks Docker to
  create it. When a signal interrupts a create, cleanup lists this run's labelled
  resources to decide: one that exists is removed, one that does not was never
  created. When Docker cannot answer, the run keeps its liveness record, so
  `--gc` can still find the run. A signal that arrives during cleanup is ignored.
- A run that is killed outright (SIGKILL, a host crash) cannot clean up. Its
  resources stay, labelled with its run id, and `devrun --gc <project>` removes
  them (section 10). Its container may keep running, because the timeout lived
  in the killed process. Until it stops it still counts against the run cap and
  keeps exclusive runs out, and once its own timeout has passed a waiting run or
  `--gc` stops it (section 10, "Survivors").
- The command runs under a timeout that is shorter than the `git-locks` lease.

## 8. Budgets and free space

- Build output: at most 20 GiB per project. Logs and test data: at most 4 GiB,
  including at most 128 MiB of logs.
- The build output of a project is the sum over its kept targets, up to two per
  worktree (one for `--worktree` runs, one for pinned runs), plus the evidence
  targets of the runs in progress. Each target can
  reach the size of a full debug build of the workspace, so a handful of
  worktrees, or a few concurrent evidence runs, can exceed 20 GiB, which a
  single per-project target could not. Until the measurement exists, remove the
  targets of deleted worktrees with `devrun --gc <project>` and keep the number
  of worktrees that build in mind.
- The runner measures the volumes after each run and fails above a budget.
  Named volumes do not enforce size, so the measurement is the guard.
- The run does not start when the host or the Docker VM has less than 50 GiB
  free.

## 9. Audit and receipts

- Before and after each run, the runner lists containers, volumes, networks, and
  images. The run fails when Docker has any new resource that is not named and
  labeled per section 5, or when the run container still exists. Concurrent
  runs of the same project create resources while the audit runs, so the audit
  must attribute each new resource by its run id label, not by its project
  alone.
- Every run writes a receipt: image digest, copy mode, source SHA, tarball
  SHA-256, command, network mode, limits, exit code, duration, audit result, and
  volume sizes.

## 10. Concurrency

Runs do not take a machine-wide lock. Several runs, including several of the
same project and of the same worktree, run at the same time; section 5 says
what they share. These rules bound how many run and give benchmarks the machine
to themselves.

- **Coordination is by file locks** (`flock`) in a per-user state directory:
  `$DEVRUN_STATE_DIR`, else `$XDG_STATE_HOME/devrun`, else
  `~/.local/state/devrun`, created with mode 0700 and refused when it belongs
  to another user or others can write it. The kernel drops a file lock when its
  process exits, however it exits, so a crash never leaves a stale lock. These
  locks coordinate runs of the same user on one machine; they are not a security
  boundary. No container can reach the state directory.
- **A cap on command phases.** At most N command phases run at once (default
  4; `--max-runs N` or `DEVRUN_MAX_RUNS`, 1 to 64). A run holds one of the slot
  files `slot-0` to `slot-<N-1>` from just before its command container starts
  until Docker confirms that the container has stopped, or until the run has
  removed it; a timeout, a signal, or an error in between does not release the
  slot earlier. Preparation, copy-in, the fetch phase, and exports do not take a
  slot. A survivor (below) in its command phase counts as a held slot: a run is
  admitted only when the free slots outnumber the survivors. A run admitted with a
  larger N can use slots that a run with a smaller N never looks at, so the cap
  in force is the one each run was given. A waiting run prints one line when it
  starts waiting and one every 30 seconds with the time waited so far, and gives
  up after `--wait` seconds (default 3600), like any other wait in the runner.
  The default suits the workstation's Docker VM (18 CPUs, about 16 GiB of
  memory): 4 runs at the default `--cpus 4` use at most 16 CPUs. Memory is
  overcommitted: 4 runs at the default `--memory 8g` could ask for 32 GiB, so
  runs that all peak at once can still exhaust the VM. Lower the cap or the
  memory limit for memory-heavy work.
- **Exclusive runs for timing.** `--exclusive` waits until no other command
  phase runs and keeps every other command phase out until it finishes.
  **Performance measurements must use `--exclusive`**; a timing taken next to
  other builds is not a measurement. Fetch phases and the preparation of other
  runs can still happen during an exclusive run; they are short and mostly
  input and output, not compilation. Once an exclusive run waits, new ordinary
  runs queue behind it, so a stream of ordinary runs cannot starve it: an
  ordinary run is admitted only by passing the `turnstile` file for an instant,
  and a waiting exclusive run holds the turnstile until it finishes. Ordinary
  runs hold `runs.lock` shared and an exclusive run holds it exclusively, so the
  exclusive run starts only after every admitted ordinary run has finished, and
  then waits until no survivor is in its command phase, saying which container
  it waits for; `--wait` bounds the whole wait.
- **Fetch phases of a project take turns.** Cargo's package-cache lock is the
  file `$CARGO_HOME/.package-cache`, and `CARGO_HOME` is on the read-only root:
  cargo cannot open it, warns, and fetches without a lock. Two concurrent fetches
  would write the same cache files, so the fetch phase holds the per-project
  file lock `fetch-<project>.lock` until its container has stopped or been
  removed, and does not take it while a survivor of the same project is fetching.
- **Pinned runs of a worktree take turns.** A `--commit` or `--history` run
  without `--evidence` holds `pinned-<project>-<source-key>.lock` from before its
  command container starts until that container has stopped or been removed, and
  does not take it while a survivor's command container uses the same pinned
  target. It takes this lock before it asks for a slot, so it never holds a slot
  or the exclusive gate while it waits for another run of its worktree. Section 5
  says what this guarantees.
- **Survivors.** A survivor is a running container that carries the role
  `dev-run`, a valid owner and run id, and a name that matches them, and whose
  run's liveness file in this state directory is free: its runner is dead.
  Admission, the fetch lock, and the pinned lock find survivors by these labels
  with `docker ps` and `docker inspect`, but only once the file locks would admit
  the run. A container of a run in another state directory, or of a live run, is
  never a survivor. A survivor's timeout died with its runner, so nothing bounds it any
  more. The rule: a waiting run, or `--gc`, stops (`docker kill`, then `docker
  wait`) a survivor once its own timeout has passed, which is what its runner would
  have done. The deadline is the container's `State.StartedAt` plus its
  `org.flyingrobots.timeout` label, compared with the daemon's current time
  (`docker info`), so host clock skew plays no part. Nothing stops a survivor
  before its timeout, or a survivor without the timeout label (from an older
  runner): those are waited for, and can be stopped by hand with `docker stop`.
  Nothing else is ever stopped. A run whose cleanup cannot remove its container
  unlocks its liveness file first and its slot and other locks after, so the
  container counts as a survivor from the moment the locks are free. One gap is
  left: when a runner is killed, the kernel releases its slot and its liveness
  file during the same exit, and a run that passes the turnstile in that instant
  can see the slot free and the runner still alive, and so start one run over
  the cap.
- **Run liveness.** Each run locks `runs/<run-id>.lock` before it creates any
  Docker resource and keeps it locked until all of them are gone. The file also
  records the project and the source key.
- **`devrun --gc <project>`** removes, after printing each item (with
  `--dry-run`, only prints):
  - the stopped containers and the per-run volumes of dead runs. A run is dead
    only when `--gc` can lock its liveness file itself, which proves that the
    process has exited. Process ids can be reused and an age proves nothing
    about use, so neither is used; `--gc` runs only when someone asks for it.
    A run whose liveness file is missing (another user or another state
    directory) is of unknown state and is left alone;
  - worktree and pinned targets whose recorded worktree path no longer exists,
    when the role, the name, the source key, and the path labels agree and no
    live run uses that source key.
  Before it decides, it stops the project's survivors whose own timeout has
  passed (with `--dry-run` it only names them); a survivor within its timeout is
  kept and named. After removing, it forgets the liveness file of a dead run only
  when nothing labelled with that run id is left. When `docker inspect` fails, it
  accepts the failure only if every resource missing from the output is also
  missing from a fresh listing; otherwise it stops with an error and forgets
  nothing, so a resource that still exists is never taken for an absent one.
  It never removes a resource without this project's owner label or without a
  valid run id or source label, a resource whose name does not match its
  labels, a running container, a volume attached to any container that it is not
  removing in the same pass, or the cargo caches. Docker itself refuses to
  remove a running container or a volume in use, which backs these rules.
- **git-locks, for visibility.** Each run registers its container under
  `host/docker/<project>-dev-run-<run-id>/` in the workstation `git-locks` store,
  with a lease longer than its timeouts and waits, and releases it at the end.
  The key is unique, so runs never conflict over it; it keeps the workstation
  registry rule `host/docker/<exact-container-name>/` true, and it keeps
  daemon-wide maintenance, which claims `host/docker/`, from starting while runs
  are active. A refusal (the key is covered by such a claim) makes the run wait.
  A missing `git-locks`, a broken store, or a failed call prints one line and
  the run goes on unregistered.
- **CI.** With `CI=true` (a single-use CI machine) there are no slots, no
  exclusive gate, no fetch lock, and no registration. The liveness file is still
  written, so `--gc` works there too.
- `scripts/build-image` and `tests/smoke-image` still claim `host/heavy-work`
  and `host/docker/devcontainers-dev-run/`. `bin/devrun` no longer claims
  either, so an image build and devrun command phases can run at the same time.

## 11. Not ours

Resources without the `org.flyingrobots.owner` label belong to other projects.
The tools never stop, remove, or prune them. Resources with the owner label but
without a run id or source label are not provably leftovers; `devrun --gc` never
removes them either.
