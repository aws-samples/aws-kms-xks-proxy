# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

Name:           xks-proxy
Version:        3.1.2

Release:        0%{?dist}
Summary:        AWS External Keystore (XKS) Proxy Service

License:        Apache-2.0
Vendor:         Amazon.com, Inc.
URL:            TBD
Source0:        %{name}-%{version}-%{release}.tar.xz

%description
AWS External Keystore (XKS) Proxy as a systemd service unit.

AWS External Key Stores allow customers to protect their data in AWS
using cryptographic keys held inside on-premises Hardware Security Modules (HSMs)
or other key managers outside of AWS.

This service implements the XKS Proxy API specification allowing AWS KMS
to access a custom external keystore using a uniform interface.

%clean

%files
/etc/systemd/system/xks-proxy.service
/etc/systemd/system/xks-proxy_cleanlogs.service
/etc/systemd/system/xks-proxy_cleanlogs.timer
/usr/sbin/xks-proxy
/usr/sbin/xks-proxy_cleanlogs

%pre

%post
systemctl daemon-reload
systemctl enable xks-proxy.service
systemctl enable xks-proxy_cleanlogs.timer

%preun
systemctl stop xks-proxy.service
systemctl stop xks-proxy_cleanlogs.timer
systemctl disable xks-proxy.service
systemctl disable xks-proxy_cleanlogs.timer

%changelog
* Mon Nov 28 2022 Hanson Char <hchar@amazon.com> - 3.1.2
- Initialize pkcs11 context with lock functions and upon failure would
  retry pkcs11 initialization without callback functions
- Fix memory corruption bugs in pkcs11 crate in context initialization
- Fix bug in closing pkcs11 session
- Mark Ctx::new_and_initialize and Ctx::initialize as unsafe
- Fix doc inconsistency
- Log pool exhaustion as a warning instead of info
- Avoid removing session from pool unnecessarily
- Always attempt to login when creating a new session
- Respond with InternalException instead of KeyNotFoundException upon CKR_GENERAL_ERROR.
- Include git hash in version + remove noise if command alien is not found
* Tue Nov 22 2022 Hanson Char <hchar@amazon.com> - 3.1.1
- Always return ValidationException upon invalid JSON payload
* Wed Nov 09 2022 Hanson Char <hchar@amazon.com> - 3.1.0
- Always enable http ping for load balancer
* Wed Sep 21 2022 Hanson Char <hchar@amazon.com> - 3.0.0
- Support full configurable of TCP keepalive probes
* Sun Sep 11 2022 Hanson Char <hchar@amazon.com> - 2.0.1
- Support configurable interval to send TCP keepalive probes
* Thu Sep 08 2022 Hanson Char <hchar@amazon.com> - 2.0.0
- Rename sigv4_access_id to sigv4_access_key_id and sigv4_secret_key to sigv4_secret_access_key
* Thu Aug 25 2022 Hanson Char <hchar@amazon.com> - 1.0.1
- Remove local patch of scratchstack-aws-signature as panic bug is fixed in v0.10.4
* Tue Aug 23 2022 Hanson Char <hchar@amazon.com> - 1.0.0
- Support verifying client dns name when mTLS is enabled
- Fix tar command for source rpm
* Sat Aug 20 2022 Hanson Char <hchar@amazon.com> - 0.3.2
- Improve docker/README.md
- Display version upon startup and /pong
* Tue Aug 16 2022 Hanson Char <hchar@amazon.com> - 0.3.1
- Fix panic at scratchstack-aws-signature due to index out of bounds: https://github.com/dacut/scratchstack-aws-signature/issues/2
- Upgrade serila_test* dependencies + fix per clippy.
* Wed Aug 03 2022 Hanson Char <hchar@amazon.com> - 0.3.0
- Always append a 2-byte AAD length of the input AAD to the AAD as input to the HSM per latest API spec.
- Fix ciphertextMetadata length to be a single byte prior to appending to the AAD as input to the HSM.
* Mon Jul 18 2022 Hanson Char <hchar@amazon.com> - 0.2.0
- Always append length of ciphertextMetadata to AAD per latest API spec
* Tue Jul 05 2022 Hanson Char <hchar@amazon.com> - 0.1.5
- Remove errorMessage from http JSON response per latest API spec
* Wed Jun 29 2022 Hanson Char <hchar@amazon.com> - 0.1.4
- Support CDIV per latest API spec
* Tue Jun 21 2022 Hanson Char <hchar@amazon.com> - 0.1.3
- Support rotation_kind in settings.toml
* Tue Jun 21 2022 Hanson Char <hchar@amazon.com> - 0.1.2
- Add is_stdout_writer_enabled and is_file_writer_enabled to settings.toml
* Fri Jun 17 2022 Hanson Char <hchar@amazon.com> - 0.1.1
- Add systemd timer for log cleaning
* Mon Mar 21 2022 Hanson Char <hchar@amazon.com> - 0.1.0
- Initial release
