# Scanner image for https://github.com/AGSQ11/SSHSpan.
#
# The audit runs offline, so this build installs the Linux system libraries Tauri links against, the pinned Rust
# toolchain, and every crate in src-tauri/Cargo.lock, then compiles the app, its tests and its examples.
# .oss-scanner/threat_model.md says how to run each of them.
# x86-64 only, like the project's own CI and release builds.

# The toolchain version that .github/workflows/ci.yml and release.yml pin (toolchain: 1.98.0). The image already has
# curl, git and a C toolchain; rustfmt and clippy are added below.
FROM rust:1.98.0-bookworm
ENV DEBIAN_FRONTEND=noninteractive

# Tauri v2 on Linux: WebKitGTK 4.1, GTK 3, the tray-icon backend, librsvg and libxdo (the same list as CI/release).
# nodejs runs the repository's renderer checks in scripts/. openssh-client provides ssh-keygen, which is handy for
# producing OpenSSH-format key fixtures and for comparing SSHSpan's output against the reference implementation.
RUN apt-get update && apt-get install -y --no-install-recommends \
      libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev libxdo-dev libssl-dev \
      build-essential pkg-config file patchelf nodejs openssh-client \
    && rm -rf /var/lib/apt/lists/* \
    && rustup component add rustfmt clippy

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# Every crate the app depends on, exactly as src-tauri/Cargo.lock pins them. --locked makes a stale lockfile fail the
# build here instead of silently resolving something else.
RUN cargo fetch --locked --manifest-path src-tauri/Cargo.toml

# The app, its integration tests and the dev-only examples (examples/dev-sshd.rs is a local SSH+SFTP server on
# 127.0.0.1:2222; examples/sftp-smoke.rs drives it). Unoptimised, so debug info is on and overflow checks are enabled.
# A step that fails fails the build, and primary_contact gets the log.
RUN cargo build --locked --manifest-path src-tauri/Cargo.toml --all-targets \
    && cargo test --locked --manifest-path src-tauri/Cargo.toml --no-run

# Run the Rust tests and the cheap renderer checks so the log shows the image works, without letting a failure abort the
# build. None of them needs a display or a network. (scripts/check-renderer-ui.js drives a real browser through
# Playwright and is not run here.)
RUN (cargo test --locked --manifest-path src-tauri/Cargo.toml || echo "WARNING: cargo test reported failures") \
    && (for s in check-renderer-globals check-ipc-args check-vendor; do node "scripts/$s.js" || echo "WARNING: $s failed"; done)

# Everything is fetched. From here on cargo must not wait for a registry that it cannot reach.
ENV CARGO_NET_OFFLINE=true
