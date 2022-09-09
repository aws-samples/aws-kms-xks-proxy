# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

Summary: Software version of a PKCS#11 Hardware Security Module
Name: softhsm
Version: 2.6.1
Release: %{?prever:0.}7%{?prever:.%{prever}}%{?dist}.2
License: BSD
Url: http://www.opendnssec.org/
Source0: %{name}-%{version}.tar.gz

BuildRequires: make
BuildRequires: openssl-devel >= 1.0.1k-6, sqlite-devel >= 3.4.2
BuildRequires: gcc-c++, pkgconfig

Requires(pre): shadow-utils
Requires: openssl-libs >= 1.0.1k-6

%define _bin_dir %{_exec_prefix}/local/bin
%define _lib_dir %{_exec_prefix}/local/lib/softhsm
 
%define _share_dir %{_exec_prefix}/local/share
%define _man_dir %{_share_dir}/man

# Disable debug build
%define  debug_package %{nil}

%description
OpenDNSSEC is providing a software implementation of a generic
cryptographic device with a PKCS#11 interface, the SoftHSM. SoftHSM is
designed to meet the requirements of OpenDNSSEC, but can also work together
with other cryptographic products because of the PKCS#11 interface.

%package devel
Summary: Development package of softhsm that includes the header files
Requires: %{name} = %{version}-%{release}, openssl-devel, sqlite-devel

%description devel
The devel package contains the libsofthsm include files

%prep
%setup -q

%build
./configure --disable-non-paged-memory --with-objectstore-backend-db \
            --with-openssl=/usr/bin --enable-ecc --disable-gost \
            --with-migrate --enable-visibility
make

%install

%make_install
rm %{buildroot}/%{_sysconfdir}/softhsm2.conf.sample
mkdir -p %{buildroot}/%{_sharedstatedir}/softhsm/tokens

%files
%{_bin_dir}/softhsm2-*

%dir %{_lib_dir}
%{_lib_dir}/libsofthsm2.*

%dir %{_man_dir}
%dir %{_man_dir}/man1
%dir %{_man_dir}/man5
%{_man_dir}/man5/softhsm2.conf.5
%{_man_dir}/man1/softhsm2-*
