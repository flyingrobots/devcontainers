# Changelog

All notable changes to this repository are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The repository has no
version numbers yet, so changes are listed under Unreleased.

## [Unreleased]

### Fixed

- Two `--commit` runs of different commits of one worktree, started close
  together, could share a build: both copies got their time before either build
  started, so cargo served the first run's binary to the second (issue #12). A
  `--worktree` run between a `--commit` run's copy and its build had the same
  effect. Pinned runs (`--commit`, `--history`) now build into their own target
  per worktree, `<project>-target-pinned-<key>`, and hold that target's lock from
  before their command starts until their container has stopped. Pinned runs of
  one worktree now run their commands one at a time.
- A `--worktree` run after a `--commit` run of the same worktree could reuse the
  commit's build for an edit older than that build (part of issue #9). The two
  modes no longer share a target.
- A container whose runner was killed with SIGKILL no longer escapes the run cap:
  it counts as a held slot, and `--exclusive` runs wait for it, until it stops.
  Once its own timeout has passed, a waiting run or `--gc` stops it. Run
  containers carry two new labels for this, `org.flyingrobots.phase` and
  `org.flyingrobots.timeout`.
- A run keeps its slot, the exclusive gate, the fetch lock, and the pinned lock
  until Docker confirms that its container has stopped or it has been removed;
  on SIGTERM they were released before cleanup had removed the container.
- A signal between Docker creating a volume or container and devrun recording it
  no longer leaves an untracked resource: devrun records the intent first, and
  cleanup lists the run's labelled resources to resolve it, keeping the run's
  liveness record when Docker cannot answer. A signal during cleanup is ignored.
- `--gc` no longer forgets a dead run when `docker inspect` fails: a failed
  inspect is accepted only when each missing resource is also missing from a
  fresh listing.

### Changed

- `bin/devrun` no longer takes the machine-wide `host/heavy-work` lock or a
  fixed per-project container name. Several runs, including several of the same
  project and the same worktree, run at the same time.
- Each run has a run id and its own container (`<project>-dev-run-<id>`), copy
  volume (`<project>-work-<id>`), and scratch volume (`<project>-scratch-<id>`),
  labelled with `org.flyingrobots.run-id`, and removes them on every exit path.
- The iteration build output is one volume per worktree,
  `<project>-target-<key>`, keyed by a hash of the worktree's real path and
  labelled with that path. Worktrees no longer share build artifacts.
- `--evidence` builds into a new volume that belongs to the one run
  (`<project>-target-evidence-<id>`) and is removed with it.
- `--commit` runs give the copied files the current time, so an older commit
  cannot reuse output built from a newer one (part of issue #9).
- Existing `<project>-target-<key>` volumes stay the targets of `--worktree`
  runs. They may still hold output of earlier `--commit` runs, which the first
  `--worktree` run after the upgrade can reuse for files older than that output;
  remove such a target with `docker volume rm` if that matters.
- Each run registers `host/docker/<project>-dev-run-<id>/` in the workstation
  git-locks store for visibility; a missing or broken git-locks no longer stops a
  run.

### Added

- A cap on concurrent command phases: `--max-runs N` or `DEVRUN_MAX_RUNS`
  (default 4), with a waiting message and a `--wait` limit.
- `--exclusive`, which runs a command phase alone on the machine, for
  benchmarks; waiting exclusive runs are not starved by new ordinary runs.
- A per-project file lock around the fetch phase, because cargo's package-cache
  lock cannot be taken on the read-only root.
- `bin/devrun --gc PROJECT [--dry-run]`, which removes the leftovers of dead
  runs and the targets of deleted worktrees, and nothing it cannot prove is a
  leftover.

### Removed

- The fixed-name volumes `<project>-work`, `<project>-scratch`,
  `<project>-target`, and `<project>-target-evidence` are no longer used. They
  are not removed automatically.
