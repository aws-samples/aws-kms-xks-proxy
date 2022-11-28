<!--
    Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
-->

# Overview

An outline and some examples on how to build a docker image for `xks-proxy` and how the image can be run in a docker container.  This document assumes you have docker installed.

## How to build a docker image for `xks-proxy`?

1. Under the project directory:

        docker build -t xks-proxy:latest .
1. Save the image to a tar file, if it needs to be exported/shared:

        docker save -o xks-proxy-docker-v3.2.0.tar xks-proxy:latest
1. Compress `xks-proxy-docker-v3.2.0.tar` into `xks-proxy-docker-v3.2.0.tar.xz` if necessary:

        xz -z -0 xks-proxy-docker-v3.2.0.tar

## How to run `xks-proxy` in a docker container?

1. Decompress `xks-proxy-docker-v3.2.0.tar.xz` to `xks-proxy-docker-v3.2.0.tar` if necessary:

       xz -d xks-proxy-docker-v3.2.0.tar.xz
1. Load the docker image if necessary:

       docker load -i xks-proxy-docker-v3.2.0.tar
1. Run `xks-proxy` in a docker container exposing port `80` (of the container) as port `80` on the running host:

        docker run --name xks-proxy -d -p 0.0.0.0:80:80 xks-proxy:latest
1. Now you can access it at
`http://<your hostname>/example/uri/path/prefix/kms/xks/v1`
or whatever URI path you've configured in `settings.toml`.

## Cheat sheet

* Remove the `xks-proxy` docker image:

        docker rmi xks-proxy:latest
* Exec into the `xks-proxy` docker container:

        docker exec -it xks-proxy bash
* List docker images:

        docker images
* List docker containers:

        docker container ls
* Ping `xks-proxy` running in docker container

        # should get back a "pong from xks-proxy v3.2.0" response
        curl http://localhost/ping
* Follow the log of the running `xks-proxy` in the docker container

        docker logs -f xks-proxy
