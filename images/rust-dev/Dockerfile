# Shared Rust development image for the flyingrobots repositories.
# Rules: docs/hygiene.md. Build with scripts/build-image, which passes the digest from base-digests.

# Fallback only. scripts/build-image always passes BASE_IMAGE from images/rust-dev/base-digests;
# keep this line equal to the 1.96.0 entry there.
ARG BASE_IMAGE=rust@sha256:58fe97504a0e4cbba5d85599619a589923d3e779472a6fb0840d58d1c4ba99d7
FROM ${BASE_IMAGE}

ARG RUST_VERSION=1.96.0
# Published checksums: https://github.com/EmbarkStudios/cargo-deny/releases/download/<version>/
#   cargo-deny-<version>-<triple>.tar.gz.sha256
ARG CARGO_DENY_VERSION=0.20.2
ARG CARGO_DENY_SHA256_AARCH64=995c82be0defc7a025cae49a2aa2644ce8245c9a3318fc4103907c6a285e8c7d
ARG CARGO_DENY_SHA256_X86_64=9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f
# Set by BuildKit (the default builder). An empty value fails the build below.
ARG TARGETARCH

LABEL org.flyingrobots.owner="devcontainers" \
      org.flyingrobots.role="base-image" \
      org.flyingrobots.rust-version="${RUST_VERSION}" \
      org.opencontainers.image.source="https://github.com/flyingrobots/devcontainers"

# The pinned base must carry the requested toolchain.
RUN test "$(rustc --version | cut -d' ' -f2)" = "${RUST_VERSION}"

# Known gap (docs/hygiene.md section 4): these components come from the rustup server at build
# time. rustup checks each one against the channel manifest for this exact version; the manifest
# itself is not pinned in this repository.
RUN rustup component add clippy rustfmt \
 && rustup target add wasm32-unknown-unknown

RUN set -eu; \
    case "${TARGETARCH}" in \
      arm64) triple=aarch64-unknown-linux-musl; sum="${CARGO_DENY_SHA256_AARCH64}" ;; \
      amd64) triple=x86_64-unknown-linux-musl;  sum="${CARGO_DENY_SHA256_X86_64}" ;; \
      *) echo "unsupported or empty TARGETARCH '${TARGETARCH}' (build with BuildKit)" >&2; exit 1 ;; \
    esac; \
    name="cargo-deny-${CARGO_DENY_VERSION}-${triple}"; \
    curl -fsSL -o /tmp/deny.tgz "https://github.com/EmbarkStudios/cargo-deny/releases/download/${CARGO_DENY_VERSION}/${name}.tar.gz"; \
    echo "${sum}  /tmp/deny.tgz" | sha256sum -c -; \
    tar -xzf /tmp/deny.tgz -C /tmp; \
    install -m 0755 "/tmp/${name}/cargo-deny" /usr/local/bin/cargo-deny; \
    rm -rf /tmp/deny.tgz "/tmp/${name}"

# Unprivileged user (fixed UID per docs/hygiene.md section 2) and the mount points for the named
# volumes (section 5). New named volumes copy the ownership of these directories, so UID 10001 can
# write to them. CARGO_HOME stays at the image path /usr/local/cargo: containers run with a
# read-only root, so no run can plant a cargo config there. Only its registry and git caches are
# volumes.
RUN groupadd --gid 10001 dev \
 && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /tmp/home --shell /usr/sbin/nologin dev \
 && mkdir -p /scratch /target /usr/local/cargo/registry /usr/local/cargo/git /tmp/home \
 && chown 10001:10001 /scratch /target /usr/local/cargo/registry /usr/local/cargo/git /tmp/home

# HOME is /tmp/home. The image creates it; a run that mounts a fresh tmpfs on /tmp must create it
# again (devrun and tests/smoke-image do).
# No RUSTUP_TOOLCHAIN: a repository's rust-toolchain.toml must match this image, or the run fails
# offline instead of silently building with another compiler. CARGO_INCREMENTAL=0 keeps audit
# builds free of incremental state. GIT_CONFIG_NOSYSTEM=1 ignores any system git config.
ENV CARGO_TARGET_DIR=/target \
    CARGO_INCREMENTAL=0 \
    HOME=/tmp/home \
    GIT_CONFIG_NOSYSTEM=1

USER 10001:10001
WORKDIR /scratch/work
