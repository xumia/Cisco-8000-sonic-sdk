# BEGIN_LEGAL
#
# Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
#
# This file and all technical concepts, proprietary knowledge, algorithms and
# intellectual property rights it contains (collectively the "Confidential Information"),
# are the sole propriety information of Cisco and shall remain at Cisco's ownership.
# You shall not disclose the Confidential Information to any third party and you
# shall use it solely in connection with operating and/or maintaining of Cisco's
# products and pursuant to the terms and conditions of the license agreement you
# entered into with Cisco.
#
# THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
# IN NO EVENT SHALL CISCO BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
# AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
# THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# END_LEGAL

include $(MakefileTemplateRoot)/Makefile.module_pre

PKG := beagle
PKG-TARGETS := libs swiglib py_lib
PKG-PATH := src/beagle

include $(MakefileTemplateRoot)/Makefile.module_vars

vendor-beagle-chip-ver := l1
vendor-beagle-rel-ver := 1.1.8
vendor-beagle-ver := beagle-$(vendor-beagle-chip-ver)-sdk-$(vendor-beagle-rel-ver)-release
vendor-beagle-release-dir := externals/beagle
vendor-beagle-extract-dir := $(beagle-build-dir)
vendor-beagle-build-dir := $(vendor-beagle-extract-dir)/$(vendor-beagle-ver)
vendor-beagle-driver-dir := $(vendor-beagle-build-dir)/driver
vendor-beagle-include-dir := $(vendor-beagle-driver-dir)/include
vendor-beagle-headers := $(vendor-beagle-include-dir)/beagle_api

vendor-beagle-configured := $(vendor-beagle-build-dir)/.configured-beagle
vendor-beagle-built := $(vendor-beagle-build-dir)/.built-beagle
vendor-beagle-tarball := $(vendor-beagle-release-dir)/$(vendor-beagle-ver).tar.gz
vendor-beagle-extract-cmd := tar xf $(vendor-beagle-tarball)
vendor-beagle-build-cmd := $(SILENT)$(MAKE) -C $(vendor-beagle-build-dir)

ifeq ($(USE_CLANG), 1)
	vendor-beagle-build-flags := PERMISSIVE=1
	vendor-build-type := $(subst -clang,,$(BUILD_TYPE))
else
	vendor-beagle-build-flags :=
	vendor-build-type := $(BUILD_TYPE)
endif

vendor-beagle-build-flags += all SWIG=$(SWIG) DEVICE_NAME=l1

vendor-beagle-slib-dir := $(vendor-beagle-build-dir)/driver/out/$(vendor-build-type)/lib_static
vendor-beagle-dlib-dir := $(vendor-beagle-build-dir)/driver/out/$(vendor-build-type)/lib
vendor-beagle-pylib-dir := $(vendor-beagle-build-dir)/driver/out/$(vendor-build-type)/pylib

vendor-beagle-fw-src := $(vendor-beagle-build-dir)/arc/beagle.hex
vendor-beagle-fw-dst := $(RES_OUTPUT_DIR)/beagle.hex

vendor-beagle-slib := $(SLIB_OUTPUT_DIR)/.beagle-slib
vendor-beagle-dlib := $(DLIB_OUTPUT_DIR)/.beagle-dlib
vendor-beagle-pylib := $(PYLIB_OUTPUT_DIR)/.beagle-pylib

vendor-beagle-sdk-pylib := bgl_sdk

vendor-beagle-sdk-so-src := $(vendor-beagle-pylib-dir)/leaba/_$(vendor-beagle-sdk-pylib)$(DYNLIB_EXT)
vendor-beagle-sdk-so-dst := $(PYLIB_OUTPUT_DIR)/beaglesdk/_$(vendor-beagle-sdk-pylib)$(DYNLIB_EXT)

vendor-beagle-sdk-pylib-src := $(vendor-beagle-pylib-dir)/leaba/$(vendor-beagle-sdk-pylib).py
vendor-beagle-sdk-pylib-dst := $(PYLIB_OUTPUT_DIR)/beaglesdk/$(vendor-beagle-sdk-pylib)cli.py

vendor-beagle-lld-pylib := bgl_lldcli

vendor-beagle-lld-so-src := $(vendor-beagle-pylib-dir)/_$(vendor-beagle-lld-pylib)$(DYNLIB_EXT)
vendor-beagle-lld-so-dst := $(PYLIB_OUTPUT_DIR)/beaglesdk/_$(vendor-beagle-lld-pylib)$(DYNLIB_EXT)

vendor-beagle-lld-pylib-src := $(vendor-beagle-pylib-dir)/$(vendor-beagle-lld-pylib).py
vendor-beagle-lld-pylib-dst := $(PYLIB_OUTPUT_DIR)/beaglesdk/$(vendor-beagle-lld-pylib).py

vendor-beagle-pylib-srcs := $(vendor-beagle-sdk-pylib-src) $(vendor-beagle-sdk-so-src) \
$(vendor-beagle-lld-pylib-src) $(vendor-beagle-lld-so-src)
vendor-beagle-pylib-dsts := $(vendor-beagle-sdk-pylib-dst) $(vendor-beagle-sdk-so-dst) \
$(vendor-beagle-lld-pylib-dst) $(vendor-beagle-lld-so-dst)

vendor-beagle-libs := hld lld common beagle_api

vendor-beagle-slibs-src := $(foreach beagle-lib, $(vendor-beagle-libs), $(vendor-beagle-slib-dir)/lib$(beagle-lib)$(ARCHIVE_EXT))
vendor-beagle-slibs-dst := $(foreach beagle-lib, $(vendor-beagle-libs), $(SLIB_OUTPUT_DIR)/libvendorbeagle$(beagle-lib)$(ARCHIVE_EXT))

vendor-beagle-dlibs-src := $(foreach beagle-lib, $(vendor-beagle-libs), $(vendor-beagle-dlib-dir)/lib$(beagle-lib)$(DYNLIB_EXT))
vendor-beagle-dlibs-dst := $(foreach beagle-lib, $(vendor-beagle-libs), $(DLIB_OUTPUT_DIR)/libvendorbeagle$(beagle-lib)$(DYNLIB_EXT))

PKG-COMPILE-PREREQS := $(vendor-beagle-slib) $(vendor-beagle-dlib) $(vendor-beagle-pylib) $(vendor-beagle-fw-dst)
PKG-INCLUDE-FLAGS := -I$(SHARED_BASE_ROOT)/src/apb -I$(SHARED_BASE_ROOT)/include \
-I$(vendor-beagle-include-dir) -I$(vendor-beagle-include-dir)/lld \
-I$(vendor-beagle-include-dir)/beagle_api \
-Ishared/externals/jansson
PKG-LINK-PREREQS := $(common-dlib) $(api-serial-dlib) $(apb-dlib) $(jansson-dlib) $(vendor-beagle-fw-dst) $(vendor-beagle-slib) $(vendor-beagle-dlib)
PKG-LINK-LIBS := -L$(DLIB_OUTPUT_DIR) -lcommon -lapi_serial -lapb -ljansson
PKG-SWIG-COMPILE-PREREQS := $(PKG-COMPILE-PREREQS)
PKG-SWIG-LINK-PREREQS := $(vendor-beagle-dlib)
PKG-SWIG-INCLUDE-FLAGS := $(PKG-INCLUDE-FLAGS)
PKG-SWIG-LINK-LIBS := -L$(DLIB_OUTPUT_DIR) -lvendorbeaglelld -lvendorbeaglehld -lvendorbeaglecommon -lvendorbeaglebeagle_api

include $(MakefileTemplateRoot)/Makefile.module_targets

beagle-prereqs := $(PKG-COMPILE-PREREQS)

beagle-slib: $(vendor-beagle-slib)

$(vendor-beagle-configured): $(vendor-beagle-tarball)
	@echo Extracting Beagle tarball
	$(SILENT)$(MKDIR) -p $(vendor-beagle-build-dir)
	$(SILENT)$(vendor-beagle-extract-cmd) -C $(vendor-beagle-extract-dir)
	$(SILENT)touch $@
	@echo Done extracting Beagle tarball

$(vendor-beagle-built): $(vendor-beagle-configured)
	@echo Building Beagle
	$(vendor-beagle-build-cmd) $(vendor-beagle-build-flags)
	$(SILENT)touch $@
	@echo Done building Beagle

$(vendor-beagle-slibs-src): $(vendor-beagle-built)

$(vendor-beagle-dlibs-src): $(vendor-beagle-built)

$(vendor-beagle-slibs-dst): $(SLIB_OUTPUT_DIR)/libvendorbeagle%: $(vendor-beagle-slib-dir)/lib%
	$(SILENT)$(MKDIR) -p $(SLIB_OUTPUT_DIR)
	$(SILENT)$(CP) $< $@
	@echo Done Copying $< from Beagle source directory

$(vendor-beagle-slib): $(vendor-beagle-slibs-dst)
	$(SILENT)$(MKDIR) -p $(SLIB_OUTPUT_DIR)
	$(SILENT)touch $@

$(vendor-beagle-dlibs-dst): $(DLIB_OUTPUT_DIR)/libvendorbeagle%: $(vendor-beagle-dlib-dir)/lib%
	$(SILENT)$(MKDIR) -p $(DLIB_OUTPUT_DIR)
	$(SILENT)$(CP) $< $@
	@echo Done Copying $< from Beagle source directory

$(vendor-beagle-dlib): $(vendor-beagle-dlibs-dst)
	$(SILENT)$(MKDIR) -p $(DLIB_OUTPUT_DIR)
	$(SILENT)touch $@

$(vendor-beagle-fw-src): $(vendor-beagle-built)

$(vendor-beagle-fw-dst): $(vendor-beagle-fw-src)
	$(SILENT)$(MKDIR) -p $(RES_OUTPUT_DIR)
	$(SILENT)$(CP) $< $@
	@echo Done Copying Beagle fw

$(vendor-beagle-pylib): $(vendor-beagle-pylib-srcs) $(vendor-beagle-pylib-dsts)
	$(SILENT)touch $@
	@echo Done Copying Beagle pylibs

$(vendor-beagle-pylib-srcs): $(vendor-beagle-built)

$(vendor-beagle-sdk-pylib-dst): $(vendor-beagle-sdk-pylib-src)
	$(SILENT)$(MKDIR) -p $(PYLIB_OUTPUT_DIR)/beaglesdk
	$(SILENT)$(CP) $< $@
	@echo Done Copying $< from Beagle source directory

$(vendor-beagle-sdk-so-dst): $(vendor-beagle-sdk-so-src)
	$(SILENT)$(MKDIR) -p $(PYLIB_OUTPUT_DIR)/beaglesdk
	$(SILENT)$(CP) $< $@
	@echo Done Copying $< from Beagle source directory

$(vendor-beagle-lld-pylib-dst): $(vendor-beagle-lld-pylib-src)
	$(SILENT)$(MKDIR) -p $(PYLIB_OUTPUT_DIR)/beaglesdk
	$(SILENT)$(CP) $< $@
	@echo Done Copying $< from Beagle source directory

$(vendor-beagle-lld-so-dst): $(vendor-beagle-lld-so-src)
	$(SILENT)$(MKDIR) -p $(PYLIB_OUTPUT_DIR)/beaglesdk
	$(SILENT)$(CP) $< $@
	@echo Done Copying $< from Beagle source directory
