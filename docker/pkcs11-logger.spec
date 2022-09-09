# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

Summary: PKCS#11 logging proxy module (Commit 4b5a2d0)
Name: pkcs11-logger
Version: 2.2.0
Release: %{?prever:0.}7%{?prever:.%{prever}}%{?dist}.2
License: BSD
Url: http://www.opendnssec.org/
Source0: %{name}-%{version}.xz

BuildRequires: make gcc-c++

%define _lib_dir %{_exec_prefix}/local/lib
 
# Disable debug build
%define  debug_package %{nil}

%description
Logger sits between the application and the original PKCS#11 library.
Application calls PKCS#11 function provided by logger, logger calls
the same function provided by the original PKCS#11 library and while
logging everything it returns the result to the application.

%prep
%setup -q

%build
cd build/linux/
sh build.sh

%install
mkdir -p %{buildroot}/usr/local/lib
cp build/linux/pkcs11-logger-x64.so %{buildroot}%{_lib_dir}

%files
%dir %{_lib_dir}
%{_lib_dir}/pkcs11-logger-x64.so
