# Docker hygiene rules

These rules hold for every image, container, volume, and network that this
repository's tools create. The runner enforces them; a rule that only lives in
this file is not enforced.

## Names and labels

- Every resource has a fixed, readable name. Nothing gets a random name.
- Every resource carries the labels `org.flyingrobots.owner=<project>` and
  `org.flyingrobots.role=<role>`. Cleanup selects by these labels, never by
  pattern or by "all unused".

| Resource | Name | Role label |
| --- | --- | --- |
| Base image | `flyingrobots/rust-dev:<rust-version>` | `base-image` |
| Run container | `<project>-dev-run` (one at a time, under a lock) | `dev-run` |
| Cargo registry cache | `flyingrobots-cargo-registry` (shared) | `cargo-registry` |
| Build output | `<project>-target` | `target` |
| Logs and test data | `<project>-scratch` | `scratch` |

## Volumes

- No anonymous volumes. Images must not declare `VOLUME`; the image smoke test
  checks that `Config.Volumes` is empty.
- Containers mount only named volumes from the table above and explicit binds of
  the repository checkout.
- A run uses `--rm`, so its writable layer is discarded. Outputs live in named
  volumes.

## Networks

- The runner never creates a network. It uses the default bridge when the
  command needs the network (for example `cargo fetch`) and `--network none`
  otherwise.
- No Docker Compose. Compose creates `<project>_default` networks and
  anonymous volumes unless every one is named by hand.

## Builds

- Images build with the default builder. No new `buildx` builder.
- A new image tag is created only for a new toolchain version, never for a new
  branch, pull request, or run.

## Budgets

- Build output: at most 20 GiB per project (the `<project>-target` volume).
- Logs and test data: at most 4 GiB per project, including at most 128 MiB of
  logs (the `<project>-scratch` volume).
- Named volumes do not enforce a size. The runner measures each volume after a
  run and fails when a budget is exceeded. The run stops before it starts when the
  host or the Docker VM has less than 50 GiB free.

## Audit

Before and after each run, the runner lists containers, volumes, and networks.
The run fails when, after it, Docker has any resource that was not there before
and is not named and labeled per the table above.

## Not ours

Resources without the `org.flyingrobots.owner` label belong to other projects.
The tools never stop, remove, or prune them.
