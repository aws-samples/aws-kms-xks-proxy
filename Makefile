# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

SPECFILE_NAME := xks-proxy.spec
SPECFILE := rpmspec/$(SPECFILE_NAME)
NAME    := $(shell rpmspec -q --queryformat "%{name}"    $(SPECFILE))
VERSION := $(shell rpmspec -q --queryformat "%{version}" $(SPECFILE))
RELEASE := $(shell rpmspec -q --queryformat "%{release}" $(SPECFILE))
TOPDIR  := $(shell rpm --eval "%{_topdir}"    )
RPMDIR  := $(shell rpm --eval "%{_rpmdir}"    )
SPECDIR := $(shell rpm --eval "%{_specdir}"   )
SOURCESDIR := $(shell rpm --eval "%{_sourcedir}")
BUILDROOT := $(shell rpm --eval %{_buildrootdir})
SOURCE_BUNDLE := $(NAME)-$(VERSION)-$(RELEASE).tar.xz
PROJECT_DIR := xks-axum
PROJECT_ROOTDIR := $(shell basename $(CURDIR))
APP_FROM_DIR := $(PROJECT_DIR)/target/release

RPMBUILDDIR_APP := $(BUILDROOT)/usr/sbin
RPMBUILD_APP := $(RPMBUILDDIR_APP)/$(NAME)

RPMBUILDIR_SERVICE_UNIT := $(BUILDROOT)/etc/systemd/system
RPMBUILD_SERVICE_UNIT := $(RPMBUILDIR_SERVICE_UNIT)/$(NAME).service

RPMBUILD_SPECFILE := $(SPECDIR)/$(SPECFILE_NAME)
RPMBUILD_SOURCEFILE := $(SOURCESDIR)/$(SOURCE_BUNDLE)
RPM := $(RPMDIR)/x86_64/$(NAME)-$(VERSION)-$(RELEASE).x86_64.rpm
DEB := $(NAME)-$(VERSION)-$(RELEASE).deb

.PHONY: release
release: $(RPM)

$(RPM): $(RPMBUILD_SPECFILE) $(RPMBUILD_SOURCEFILE) $(RPMBUILD_APP) $(RPMBUILD_SERVICE_UNIT)
	rpmbuild -ba --noclean $(RPMBUILD_SPECFILE) --buildroot=$(BUILDROOT)
        # Symlink to the rpm so we can use a "constant" name by CodeBuild in buildspec.yml
        # and CodeDeploy in appspec.yml
	ln -s $(RPM) $(APP_FROM_DIR)/aws-kms-xks-proxy.rpm

ifeq (, $(shell which alien))
	@echo "No command alien found"
else
ifeq (, $(shell which sudo))
	alien $(RPM)
else
	sudo alien $(RPM)
endif
endif

$(RPMBUILD_SPECFILE):
	for dir in BUILD RPMS SOURCES SPECS SRPMS; do \
		mkdir -p ~/rpmbuild/$$dir; \
	done
	cp $(SPECFILE) $@

$(RPMBUILD_SOURCEFILE):
	cargo clean --manifest-path=$(PROJECT_DIR)/Cargo.toml && \
		cd .. && \
		tar cJfh $@ \
			--exclude=$(PROJECT_ROOTDIR)/.git \
			--exclude=$(PROJECT_ROOTDIR)/.gitignore \
			--exclude=$(PROJECT_ROOTDIR)/Config \
			$(PROJECT_ROOTDIR)

$(RPMBUILD_APP): $(APP_FROM_DIR)/$(NAME)
	mkdir -p $(RPMBUILDDIR_APP)
	cp scripts/* $(RPMBUILDDIR_APP)/
	cp $(APP_FROM_DIR)/$(NAME) $@

$(APP_FROM_DIR)/$(NAME):
	cargo build --release --manifest-path=$(PROJECT_DIR)/Cargo.toml

$(RPMBUILD_SERVICE_UNIT):
	mkdir -p $(RPMBUILDIR_SERVICE_UNIT)
	cp systemd/* $(RPMBUILDIR_SERVICE_UNIT)/

# A convenient target to install all the necessary rpm build tools
.PHONY: install_rpm_tools
install_rpm_tools:
	sudo yum install -y rpmdevtools rpm-build rpm-devel rpmlint
	@touch $@

.PHONY: clean
clean:
	rm -f $(RPM)
	rm -rf $(APP_FROM_DIR)

.PHONY: distclean
distclean: clean
	rm -rf $(TOPDIR)
	rm -f install_rpm_tools

