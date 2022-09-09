<!--
    Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
-->

# Overview

An outline and some examples on how to build a docker image for `xks-proxy` and how the image can be run in a docker container.  This document assumes you have docker installed, and have some basic knowlege of how to build an rpm in a Centos-ish Linux environment.

## How to build a docker image for `xks-proxy`?

This is an outline of how to build a docker image for `xks-proxy`, including information on how to build the rpms as input to the docker image.

1. Build the rpm for `softhsm` from the source bundle [softhsm-2.6.1.tar.gz](https://dist.opendnssec.org/source/softhsm-2.6.1.tar.gz) using [softhsm.spec](softhsm.spec) after downloading the source bundle to this directory.  Copy the rpm to this directory.
1. Build the rpm for `pkcs11-logger` from source using [pkcs11-logger.spec](pkcs11-logger.spec).  For instance, the source bundle `pkcs11-logger-2.2.0.xz` was once successfully packaged from the commit [4b5a2d0](https://github.com/Pkcs11Interop/pkcs11-logger/commit/4b5a2d004b9dcdb3d60d02b28e0d2fffaca8c603) at https://github.com/Pkcs11Interop/pkcs11-logger.  Copy the rpm to this directory.  Note, however, this rpm is for diagnostic and debugging purposes only.  Therefore you may choose to omit it by adusting [Dockerfile](Dockerfile) as necessary.
1. Build the rpm for `xks-proxy` via `make` under the [Rust-xks-proxy](https://code.amazon.com/packages/Rust-xks-proxy/trees/mainline) package on a Centos-ish Linux distro.  Copy the rpm to this directory.
1. Copy [settings_docker.toml](../xks-axum/configuration/settings_docker.toml) into `settings.toml` in this directory.  Adjust the configuration in `settings.toml` as needed.
1. Adjust [Dockerfile](Dockerfile) as needed.
1. Build a docker image for `xks-proxy`:

        docker build -t xks-proxy:v1.0.1 .
1. Save the image to a tar file, if it needs to be exported/shared:

        docker save -o xks-proxy-docker-v1.0.1.tar xks-proxy:v1.0.1
1. Compress `xks-proxy-docker-v1.0.1.tar` into `xks-proxy-docker-v1.0.1.tar.xz` if necessary:

        xz -z -0 xks-proxy-docker-v1.0.1.tar

## How to run `xks-proxy` in a docker container?

1. Decompress `xks-proxy-docker-v1.0.1.tar.xz` to `xks-proxy-docker-v1.0.1.tar` if necessary:

       xz -d xks-proxy-docker-v1.0.1.tar.xz
1. Load the docker image if necessary:

       docker load -i xks-proxy-docker-v1.0.1.tar
1. Run `xks-proxy` in a docker container exposing port `80` (of the container) as port `8000` on the running host:

        docker run --name xks-proxy -d -p 0.0.0.0:80:80 xks-proxy:v1.0.1
1. Now you can access it at
`http://<your hostname>/example/uri/path/prefix/kms/xks/v1`
or whatever URI path you've configured in `settings.toml`.

## Cheat sheet

* Remove the `xks-proxy` docker image:

        docker rmi xks-proxy:v1.0.1
* Exec into the `xks-proxy` docker container:

        docker exec -it xks-proxy bash
* List docker images:

        docker images
* List docker containers:

        docker container ls
* Ping `xks-proxy` running in docker container

        # should get back a "pong from xks-proxy v1.0.1" response
        curl http://localhost/ping
* Follow the log of the running `xks-proxy` in the docker container

        docker logs -f xks-proxy
