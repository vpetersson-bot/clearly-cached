# Static musl build into scratch. The service opens one listening socket and
# makes outbound HTTPS calls; it needs no shell, no package manager and no libc
# in the final image, so it should not carry them.
#
# TLS roots are compiled in via reqwest's webpki-roots feature rather than read
# from /etc/ssl, which is what makes scratch viable.
FROM rust:1.90-alpine AS builder

# musl-dev/gcc for the linker and the C dependencies of the TLS stack.
RUN apk add --no-cache musl-dev gcc

WORKDIR /build

# Dependencies first, so a source-only change does not re-resolve or rebuild
# the dependency graph.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
    && echo 'fn main() {}' > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src

COPY src ./src
# cargo skips rebuilding when only mtime changed; touch forces the real build.
RUN touch src/main.rs && cargo build --release --locked

FROM scratch
COPY --from=builder /build/target/release/enrichment-cache /enrichment-cache

# Non-root by uid: scratch has no /etc/passwd to name a user in.
USER 65532:65532

EXPOSE 8080
ENTRYPOINT ["/enrichment-cache"]
