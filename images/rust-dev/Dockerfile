# Shared Rust development image for the flyingrobots repositories.
# Rules: docs/hygiene.md. Build only with scripts/build-image, which passes a digest-pinned base.
ARG BASE_IMAGE=rust@sha256:58fe97504a0e4cbba5d85599619a589923d3e779472a6fb0840d58d1c4ba99d7
FROM ${BASE_IMAGE}

ARG RUST_VERSION
ARG CARGO_DENY_VERSION=0.20.2
ARG CARGO_DENY_SHA256_AARCH64=995c82be0defc7a025cae49a2aa2644ce8245c9a3318fc4103907c6a285e8c7d
ARG CARGO_DENY_SHA256_X86_64=9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f
ARG TARGETARCH

LABEL org.flyingrobots.owner="devcontainers" \
      org.flyingrobots.role="base-image" \
      org.flyingrobots.rust-version="${RUST_VERSION}" \
      org.opencontainers.image.source="https://github.com/flyingrobots/devcontainers"

# The base image must already carry the requested toolchain.
RUN test "$(rustc --version | cut -d' ' -f2)" = "${RUST_VERSION}"

RUN rustup component add clippy rustfmt \
 && rustup target add wasm32-unknown-unknown \
 && rustup default "${RUST_VERSION}"

RUN set -eu; \
    case "${TARGETARCH}" in \
      arm64) triple=aarch64-unknown-linux-musl; sum="${CARGO_DENY_SHA256_AARCH64}" ;; \
      amd64) triple=x86_64-unknown-linux-musl;  sum="${CARGO_DENY_SHA256_X86_64}" ;; \
      *) echo "unsupported TARGETARCH ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    name="cargo-deny-${CARGO_DENY_VERSION}-${triple}"; \
    curl -fsSL -o /tmp/deny.tgz "https://github.com/EmbarkStudios/cargo-deny/releases/download/${CARGO_DENY_VERSION}/${name}.tar.gz"; \
    echo "${sum}  /tmp/deny.tgz" | sha256sum -c -; \
    tar -xzf /tmp/deny.tgz -C /tmp; \
    install -m 0755 "/tmp/${name}/cargo-deny" /usr/local/bin/cargo-deny; \
    rm -rf /tmp/deny.tgz "/tmp/${name}"

# Unprivileged user and the mount points for the named volumes (docs/hygiene.md section 5).
# New named volumes copy this ownership, so the user can write to them.
RUN groupadd --gid 10001 dev \
 && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /tmp/home --shell /usr/sbin/nologin dev \
 && mkdir -p /scratch /target /cargo-registry \
 && chown 10001:10001 /scratch /target /cargo-registry \
 && chmod -R go-w /usr/local/rustup /usr/local/cargo

ENV RUSTUP_TOOLCHAIN=${RUST_VERSION} \
    CARGO_HOME=/cargo-registry \
    CARGO_TARGET_DIR=/target \
    CARGO_INCREMENTAL=0 \
    HOME=/tmp/home \
    GIT_CONFIG_NOSYSTEM=1 \
    PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

USER 10001:10001
WORKDIR /scratch/work
