# devcontainers

Shared development containers for the flyingrobots Rust repositories
(Geordi, Bunny, Echo, ninelives). Builds, tests, and toolchains run inside these
containers, never on the host.

- One base image per Rust toolchain, pinned to the version in each repository's
  `rust-toolchain.toml`.
- One guarded runner that every repository calls. The runner claims `git-locks`
  keys, applies a timeout and resource limits, mounts only named volumes and
  binds, and audits Docker for litter before and after each run.

The rules are in [`docs/hygiene.md`](docs/hygiene.md). Work is tracked in GitHub
Issues with `issue-dag/2` frontmatter.

## Build and test the base image

```sh
scripts/build-image 1.96.0   # builds flyingrobots/rust-dev:1.96.0 under the git-locks keys
tests/smoke-image 1.96.0     # checks it in offline, read-only, unprivileged containers
```

Pinned base digests live in `images/rust-dev/base-digests`, one line per Rust
version. The image runs as UID 10001. Mount points for the named volumes:
`/scratch` (copy, logs, exports), `/target` (build output),
`/usr/local/cargo/registry`, and `/usr/local/cargo/git` (cargo caches).

The guarded runner `bin/devrun` is not here yet (flyingrobots/devcontainers#3
and #5). Until it lands, these two scripts are the only supported way to use
Docker from this repository.
