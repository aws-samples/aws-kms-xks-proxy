<!--
    Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
-->

## Building pkcs11-logger module on Mac OSX

If you want to make use of the `pkcs11-logger module` for testing on Mac OSX, you can build it from source by git cloning the [pkcs11-logger git repository](https://github.com/Pkcs11Interop/pkcs11-logger.git) and follow the [build instructions for Mac OSX](https://github.com/Pkcs11Interop/pkcs11-logger#mac-os-x).

If you ran into build problems related to [32-bits support being removed by Apple](https://github.com/Pkcs11Interop/pkcs11-logger/issues/7), you can try applying [this pull request](https://github.com/Pkcs11Interop/pkcs11-logger/pull/8).

Alternatively, you can git clone [this git repository](https://github.com/hansonchar/pkcs11-logger.git) which has a "pull-8" branch that already has the above pull request applied.
