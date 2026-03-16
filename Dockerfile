# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# See docker/README.md for more information.

FROM ubuntu as builder

ENV HOME=/root
ENV RUST_VERSION=1.75.0
RUN mkdir -p $HOME/aws-kms-xks-proxy
COPY ./xks-axum $HOME/aws-kms-xks-proxy/xks-axum

RUN apt-get update -y
RUN apt-get install -y softhsm2 opensc curl build-essential

RUN softhsm2-util --init-token --slot 0 --label "xks-proxy" --so-pin 1234 --pin 1234
RUN pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
                --token-label xks-proxy --login --login-type user \
                --keygen --id F0 --label foo --key-type aes:32 \
                --pin 1234
RUN curl "https://static.rust-lang.org/dist/rust-$RUST_VERSION-x86_64-unknown-linux-gnu.tar.gz" -o rust.tar.gz && \
    tar -xvf rust.tar.gz && cd "rust-$RUST_VERSION-x86_64-unknown-linux-gnu" && ./install.sh
ENV PATH="$HOME/.cargo/bin:$PATH"

RUN mkdir -p /var/local/xks-proxy/.secret
COPY ./xks-axum/configuration/settings_docker.toml /var/local/xks-proxy/.secret/settings.toml

ENV PROJECT_DIR=$HOME/aws-kms-xks-proxy/xks-axum
RUN cargo build --release --manifest-path=$PROJECT_DIR/Cargo.toml && \
        cp $PROJECT_DIR/target/release/xks-proxy /usr/sbin/xks-proxy

FROM ubuntu

COPY --from=builder /etc/softhsm/ /etc/softhsm/
COPY --from=builder /var/lib/softhsm/ /var/lib/softhsm/

COPY --from=builder /usr/lib/ /usr/lib/
COPY --from=builder /usr/bin/ /usr/bin/

COPY --from=builder /var/local/ /var/local/

COPY --from=builder /usr/sbin/xks-proxy /usr/sbin/xks-proxy

EXPOSE 80

ENV XKS_PROXY_SETTINGS_TOML=/var/local/xks-proxy/.secret/settings.toml \
    RUST_BACKTRACE=1

ENTRYPOINT ["/usr/sbin/xks-proxy"]
