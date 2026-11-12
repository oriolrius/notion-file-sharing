# syntax=docker/dockerfile:1
# Static musl binary → distroless (no shell, no libc, non-root). Built only by GitHub Actions.

FROM rust:1.99.1-alpine3.22 AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
# Dependencies first (cached layer while only the sources change).
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
 && cargo build --release --locked \
 && rm -rf src target/release/deps/nfs-* target/release/nfs*
COPY src ./src
COPY templates ./templates
COPY assets ./assets
RUN touch src/main.rs && cargo build --release --locked && strip target/release/nfs \
 && ./target/release/nfs --version | grep -q "^nfs "

# `docker buildx build --target binary --output type=local,dest=dist .` exports only the binary.
FROM scratch AS binary
COPY --from=build /src/target/release/nfs /nfs

FROM gcr.io/distroless/static-debian13:nonroot
LABEL org.opencontainers.image.source="https://github.com/oriolrius/notion-file-sharing" \
      org.opencontainers.image.description="NFS: secure, expiring links to files stored in Notion" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /src/target/release/nfs /nfs
ENV NFS_CONFIG=/etc/nfs/config.toml
EXPOSE 8080 9100
USER nonroot:nonroot
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD ["/nfs", "health"]
ENTRYPOINT ["/nfs"]
CMD ["serve"]
