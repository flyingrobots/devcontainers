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
