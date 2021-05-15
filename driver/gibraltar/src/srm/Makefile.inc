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

PKG := srm
PKG-TARGETS := libs swiglib py_lib
PKG-PATH := src/srm

include $(MakefileTemplateRoot)/Makefile.module_vars

# General definitions
vendor-srm-ver := 0.33.0.1670

vendor-srm-build-dir := $(srm-build-dir)/$(vendor-srm-ver)
vendor-srm-configured := $(vendor-srm-build-dir)/.configured
vendor-srm-built := $(vendor-srm-build-dir)/.built
vendor-srm-src-dir := $(vendor-srm-build-dir)/srm_public_release_$(vendor-srm-ver)/api
vendor-srm-ucode-dir := $(vendor-srm-build-dir)/srm_public_release_$(vendor-srm-ver)/ucode
vendor-srm-serdes-file := srm_app_fw_image_0_33_1_1688.txt
ifeq ($(PREBUILT_DEPENDS), 1)
	vendor-srm-tarball :=
	vendor-srm-ucode := prebuilt/res/$(vendor-srm-serdes-file)
	vendor-srm-slib-src := prebuilt/lib_static/libvendorsrm.a
	vendor-srm-dlib-src := prebuilt/lib/libvendorsrm.so
	srm-dlib-src := prebuilt/lib/libsrm.so
	srm-slib-src := prebuilt/lib_static/libsrm.a
	vendor-srm-include-dir := prebuilt/include/srm
else
	#vendor-srm-tarball := externals/srm/srm_public_release_$(vendor-srm-ver).zip
	vendor-srm-tarball := externals/srm/srm_public_release_$(vendor-srm-ver).tar.gz
	vendor-srm-ucode := externals/srm/srm_fw_0.33.1.1688.txt
	vendor-srm-slib-src := $(vendor-srm-src-dir)/libvendorsrm.a
	vendor-srm-dlib-src := $(vendor-srm-src-dir)/libvendorsrm.so
	srm-slib-src :=
	srm-dlib-src :=
	vendor-srm-include-dir := $(vendor-srm-src-dir)
endif
#vendor-srm-extract-cmd := unzip $(vendor-srm-tarball) -d
vendor-srm-extract-cmd := tar zxf $(vendor-srm-tarball) -C

vendor-firmware-serdes := $(RES_OUTPUT_DIR)/$(vendor-srm-serdes-file)

srm-slib := $(SLIB_OUTPUT_DIR)/libsrm$(ARCHIVE_EXT)
srm-dlib := $(DLIB_OUTPUT_DIR)/libsrm$(DYNLIB_EXT)

vendor-srm-slib := $(SLIB_OUTPUT_DIR)/libvendorsrm$(ARCHIVE_EXT)
vendor-srm-dlib := $(DLIB_OUTPUT_DIR)/libvendorsrm$(DYNLIB_EXT)

SRM_PATCH_FILES = $(wildcard src/srm/*.patch)

PKG-COMPILE-PREREQS := $(vendor-srm-configured)
PKG-INCLUDE-FLAGS := -I$(SHARED_BASE_ROOT)/include -I$(vendor-srm-include-dir) -I$(vendor-srm-include-dir)/platform
PKG-LINK-PREREQS := $(common-dlib) $(api-serial-dlib) $(apb-dlib) $(vendor-firmware-serdes)
PKG-SWIG-INCLUDE-FLAGS := -I$(SHARED_BASE_ROOT)/include
PKG-SWIG-LINK-PREREQS := $(vendor-srm-dlib) $(api-serial-dlib) $(common-dlib) $(apb-dlib)
PKG-SWIG-INCLUDE-FLAGS += -I$(vendor-srm-include-dir) -I$(vendor-srm-include-dir)/platform

ifeq ($(PREBUILT_DEPENDS), 0)
	PKG-INCLUDE-FLAGS += -I$(INCLUDE_OUTPUT_DIR) -I$(SHARED_INCLUDE_OUTPUT_DIR) -I../../externals/jansson
	PKG-COMPILE-PREREQS += $(nplapi-configured)
	PKG-SWIG-LINK-PREREQS += $(lld-swig-dlib)
	PKG-LINK-PREREQS += $(vendor-firmware-serdes)
else
	PKG-SWIG-LINK-PREREQS += $(vendor-firmware-serdes)
endif

PKG-CXX-EXTRA-FLAGS := -DIP_HAS_DIAGNOSTIC_DUMPS=1 -DIP_HAS_MATH_DOT_H=1 -DIP_HAS_DIRECT_DOWNLOAD=1 -DIP_HAS_INLINE_APP_FW=1
PKG-SWIG-EXTRA-FLAGS := -DIP_HAS_DIAGNOSTIC_DUMPS=1 -DIP_HAS_MATH_DOT_H=1
PKG-LINK-LIBS := -L$(DLIB_OUTPUT_DIR) -lcommon -lapi_serial -lapb
PKG-SWIG-LINK-LIBS := -L$(DLIB_OUTPUT_DIR) -lcommon -lapi_serial -lvendorsrm -lapb -lrt

$(PKG)-as-dependency := $($(PKG)-as-dependency) $(vendor-srm-dlib) $(vendor-srm-slib)

include $(MakefileTemplateRoot)/Makefile.module_targets

# Dependencies and flags for compilation
$(srm-swig-wrap-src): $(vendor-srm-configured)

# Rules for the SRM library
vendor-srm-configured: $(vendor-srm-configured)

$(vendor-srm-configured): $(vendor-srm-tarball)
	@echo Extracting SRM SDK
ifeq ($(PREBUILT_DEPENDS), 1)
	@$(MKDIR) -p $(@D)
else
	@$(RM) -rf $(@D)
	@$(MKDIR) -p $(@D)
	@$(vendor-srm-extract-cmd) $(@D)
	$(foreach pfile,$(SRM_PATCH_FILES), patch -p0 -d $(vendor-srm-src-dir) < $(pfile);)
endif
	@touch $@
	@echo Done configuring the SRM library.

vendor-srm-built: $(vendor-srm-built)

$(vendor-srm-built): $(vendor-srm-configured)
ifeq ($(PREBUILT_DEPENDS), 0)
	@echo Start building SRM library.
	$(SILENT)cd $(vendor-srm-src-dir) && \
            $(CC) --std=c99 $(CFLAGS) $(C_EXTRA_FLAGS) $(INCLUDE_FLAGS) \
                -I . -I platform -o ip_rtos.o -c platform/ip_rtos.c
	$(SILENT)cd $(vendor-srm-src-dir) && \
            $(CC) --std=c99 $(CFLAGS) $(C_EXTRA_FLAGS) $(INCLUDE_FLAGS) \
                -I . -I platform -o srm_api.o -c srm_api.c
	$(SILENT)cd $(vendor-srm-src-dir) && \
            $(CC) $(CFLAGS) -shared -o libvendorsrm.so ip_rtos.o srm_api.o
	$(SILENT)cd $(vendor-srm-src-dir) && $(AR) $(AR_FLAGS) $(AR_OUTPUT_FLAG) libvendorsrm.a ip_rtos.o srm_api.o
endif
	@touch $@
	@echo Done building SRM library.

# these static libraries are called from hld Makefile
vendor-srm-slib: $(vendor-srm-slib)
srm-slib: $(srm-slib)

$(vendor-srm-src-dir)/libvendorsrm.a: $(vendor-srm-built)

$(vendor-srm-slib): $(vendor-srm-slib-src)
	@$(MKDIR) -p $(@D)
	@$(CP) $< $@


ifeq ($(PREBUILT_DEPENDS), 1)
$(srm-slib): $(srm-slib-src)
	@$(MKDIR) -p $(@D)
	@$(CP) $< $@

$(srm-dlib): $(srm-dlib-src)
	@$(MKDIR) -p $(@D)
	@$(CP) $< $@
endif

vendor-srm-dlib: $(vendor-srm-dlib)

$(vendor-srm-src-dir)/libvendorsrm.so: $(vendor-srm-built)

$(vendor-srm-dlib): $(vendor-srm-dlib-src)
	@$(MKDIR) -p $(@D)
	@$(CP) $< $@

$(vendor-srm-ucode-dir)/$(vendor-srm-serdes-file): $(vendor-srm-built)

# Copy SRM firmware file and remove any comments from the file (line starts with "#").
# $(vendor-firmware-serdes): $(vendor-srm-ucode-dir)/$(vendor-srm-serdes-file)
ifeq ($(PREBUILT_DEPENDS), 0)
$(vendor-firmware-serdes): $(vendor-srm-ucode)
	@$(MKDIR) -p $(@D)
	@sed -e "s/^#.*/# /" $< > $@
else
$(vendor-firmware-serdes): prebuilt/res/$(vendor-srm-serdes-file)
	@$(MKDIR) -p $(@D)
	@$(CP) $< $@
endif
