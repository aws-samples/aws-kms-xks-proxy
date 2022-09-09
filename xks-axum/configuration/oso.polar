# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Sample polar file for testing secondary authorization.  More details at:
#
#     https://docs.osohq.com/rust/reference/polar/polar-syntax.html
#     https://docs.osohq.com/rust/reference/polar/classes.html

# Secondary auth for "encrypt" requests
allow(uri_path_prefix: String, "encrypt", metadata: EncryptMetadata)
    if uri_path_prefix != ""
    # and metadata.awsPrincipalArn = "alice"
    and metadata.kmsOperation = "Encrypt"
    and (metadata.kmsViaService = nil
    or "ebs" in metadata.kmsViaService);

# Secondary auth for "decrypt" requests
allow(uri_path_prefix: String, "decrypt", metadata: EncryptMetadata)
    if uri_path_prefix != ""
    # and metadata.awsPrincipalArn = "bob"
    and metadata.kmsOperation in ["Encrypt", "Decrypt"]
    and (metadata.kmsViaService = nil
    or "ebs" in metadata.kmsViaService);

# Secondary auth for "metadata" requests
allow(uri_path_prefix: String, "metadata", metadata: GetKeyMetadata)
    if uri_path_prefix != ""
    and metadata.kmsOperation = "DescribeKey";

# Secondary auth for "health" requests
allow(uri_path_prefix: String, "health", metadata: GetHealthMetadata)
    if uri_path_prefix != ""
    and metadata.kmsOperation in [
        "CreateCustomKeystore",
        "ConnectCustomKeystore",
        "UpdateCustomKeystore",
    ];
