# Changelog

All notable changes to this repository are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The repository has no
version numbers yet, so changes are listed under Unreleased.

## [Unreleased]

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
