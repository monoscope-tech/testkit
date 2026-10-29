# testkit with a browser: `docker run --rm -v "$PWD:/work" ghcr.io/apitoolkit/testkit test`
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --bin testkit

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      chromium fonts-liberation fonts-noto-core fonts-noto-color-emoji ca-certificates python3 procps git \
    && rm -rf /var/lib/apt/lists/*
ENV TESTKIT_CHROME=/usr/bin/chromium CHROME=/usr/bin/chromium TESTKIT_NO_SANDBOX=1 TESTKIT_BIN=/usr/local/bin/testkit
COPY --from=build /src/target/release/testkit /usr/local/bin/testkit
WORKDIR /work
ENTRYPOINT ["testkit"]
