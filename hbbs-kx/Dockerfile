# hbbs + hbbr из rustdesk-server с патчем patch_kx.py: TCP-обмен ключами (как в Pro) для клиентов RustDesk 1.5+,
# вошедших в аккаунт. Без патча такие клиенты получают «Failed to secure tcp: deadline has elapsed».
# Сборка: docker build -t rds-hbbs-kx:1.1.16-kx1 hbbs-kx/
ARG RUSTDESK_SERVER_TAG=1.1.16

FROM rust:1.88-bookworm AS build
ARG RUSTDESK_SERVER_TAG
RUN apt-get update && apt-get install -y --no-install-recommends git python3 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN git clone --depth 1 --branch "${RUSTDESK_SERVER_TAG}" --recurse-submodules --shallow-submodules \
        https://github.com/rustdesk/rustdesk-server.git .
COPY patch_kx.py /patch_kx.py
RUN python3 /patch_kx.py src/rendezvous_server.rs \
 && cargo build --release --locked --bin hbbs --bin hbbr

FROM debian:bookworm-slim
COPY --from=build /src/target/release/hbbs /src/target/release/hbbr /usr/bin/
WORKDIR /root
