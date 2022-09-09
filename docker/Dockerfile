# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

FROM amazonlinux as builder

COPY softhsm-*.x86_64.rpm \
     xks-proxy-*.x86_64.rpm \
     pkcs11-logger-*.x86_64.rpm ./

RUN yum update -y && yum upgrade -y && \
    yum install -y \
        softhsm-*.x86_64.rpm \
        pkcs11-logger-*.x86_64.rpm \
        # Provide command pkcs11-tool
        opensc \
        xks-proxy-*.x86_64.rpm && \
    # Initialize token "xks-proxy" at slot 0
    softhsm2-util --init-token --slot 0 --label "xks-proxy" --so-pin 1234 --pin 1234 && \
    # Generate an 256-bit AES key "foo"
    pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so \
        --token-label xks-proxy \
        --login --login-type user --pin 1234 \
        --keygen --id F0 --label foo --key-type aes:32 && \
    mkdir -p /var/local/xks-proxy/logs && \
    mkdir -p /var/local/xks-proxy/.secret && \
    rm ./*.rpm && \
    yum remove -y opensc

COPY settings.toml /var/local/xks-proxy/.secret/

FROM amazonlinux
COPY --from=builder /etc/softhsm2.conf /etc/softhsm2.conf
COPY --from=builder /var/lib/softhsm/ /var/lib/softhsm/

COPY --from=builder /usr/local/lib/ /usr/local/lib/
COPY --from=builder /usr/local/bin/ /usr/local/bin/

COPY --from=builder /etc/pki/nssdb/pkcs11.txt /etc/pki/nssdb/pkcs11.txt
COPY --from=builder /etc/pkcs11/ /etc/pkcs11/
COPY --from=builder /usr/lib64/pkcs11/ /usr/lib64/pkcs11/
COPY --from=builder /var/local/ /var/local/

COPY --from=builder /etc/systemd/system/multi-user.target.wants/xks-proxy.service /etc/systemd/system/multi-user.target.wants/xks-proxy.service
COPY --from=builder /etc/systemd/system/timers.target.wants/xks-proxy_cleanlogs.timer /etc/systemd/system/timers.target.wants/xks-proxy_cleanlogs.timer
COPY --from=builder /etc/systemd/system/xks-proxy.service /etc/systemd/system/xks-proxy.service
COPY --from=builder /etc/systemd/system/xks-proxy_cleanlogs.service /etc/systemd/system/xks-proxy_cleanlogs.service
COPY --from=builder /etc/systemd/system/xks-proxy_cleanlogs.timer /etc/systemd/system/xks-proxy_cleanlogs.timer
COPY --from=builder /usr/sbin/xks-proxy /usr/sbin/xks-proxy
COPY --from=builder /usr/sbin/xks-proxy_cleanlogs /usr/sbin/xks-proxy_cleanlogs

EXPOSE 80

ENV XKS_PROXY_SETTINGS_TOML=/var/local/xks-proxy/.secret/settings.toml \
    RUST_BACKTRACE=1

# You can use the following environment variables to override the PKCS11 related
# configurations

# Specifies the file path to the PKCS#11 library.
# ENV PKCS11_HSM_MODULE=/usr/local/lib/pkcs11-logger-x64.so

# https://github.com/Pkcs11Interop/pkcs11-logger
# Path to the original PKCS#11 library.
# ENV PKCS11_LOGGER_LIBRARY_PATH=/usr/local/lib/softhsm/libsofthsm2.so

# Path to the pkcs11-logger log file.
# ENV PKCS11_LOGGER_LOG_FILE_PATH=/var/local/xks-proxy/logs/pkcs11-logger-output.log

# Specifies a bit mask that controls multiple pkcs11-logger features.
# ENV PKCS11_LOGGER_FLAGS=0
ENTRYPOINT ["/usr/sbin/xks-proxy"]
