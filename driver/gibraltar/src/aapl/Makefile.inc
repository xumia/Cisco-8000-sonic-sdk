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

PKG := aapl
PKG-TARGETS := swiglib
PKG-PATH := src/aapl

include $(MakefileTemplateRoot)/Makefile.module_vars

# General AAPL definitions
aapl-ver := aapl-2.7.3
aapl-avago-firmware-serdes-ver := 0x109e_208d_0a4
aapl-avago-firmware-serdes-file := serdes.$(aapl-avago-firmware-serdes-ver).rom
aapl-avago-firmware-sbus-master-ver := 0x1024_2001
aapl-avago-firmware-sbus-master-file := sbus_master.$(aapl-avago-firmware-sbus-master-ver).rom
aapl-avago-firmware-pcie-ver := 0x107b_2447
aapl-avago-firmware-pcie-file := pcie.$(aapl-avago-firmware-pcie-ver).rom
aapl-avago-firmware-hbm-ver := 0x055f
aapl-avago-firmware-hbm-file := hbm.$(aapl-avago-firmware-hbm-ver)_2002.rom
aapl-avago-firmware-hbm-mbist-file := hbm.$(aapl-avago-firmware-hbm-ver)_2012.rom

aapl-avago-build-dir := $(aapl-build-dir)/$(aapl-ver)
aapl-avago-slib := $(SLIB_OUTPUT_DIR)/libAAPL$(ARCHIVE_EXT)
aapl-avago-dlib := $(DLIB_OUTPUT_DIR)/libAAPL$(DYNLIB_EXT)
aapl-avago-configured := $(aapl-avago-build-dir)/.configured
aapl-avago-built := $(aapl-avago-build-dir)/.built

aapl-avago-firmware-serdes := $(RES_OUTPUT_DIR)/$(aapl-avago-firmware-serdes-file)
aapl-avago-firmware-sbus-master := $(RES_OUTPUT_DIR)/$(aapl-avago-firmware-sbus-master-file)
aapl-avago-firmware-pcie := $(RES_OUTPUT_DIR)/$(aapl-avago-firmware-pcie-file)
aapl-avago-firmware-hbm := $(RES_OUTPUT_DIR)/$(aapl-avago-firmware-hbm-file)
aapl-avago-firmware-hbm-mbist := $(RES_OUTPUT_DIR)/$(aapl-avago-firmware-hbm-mbist-file)

PATCH_FILES = $(wildcard src/aapl/*.patch)
PKG-INCLUDE-FLAGS := -I$(ZLIB_INC_DIR) -Iinclude -I$(aapl-avago-build-dir)/src/include
PKG-COMPILE-PREREQS := $(aapl-avago-configured)
PKG-SWIG-INCLUDE-FLAGS := -Iinclude
PKG-SWIG-LINK-LIBS := -L$(DLIB_OUTPUT_DIR) -llld -lapi_serial -lrt -lz -lAAPL
PKG-SWIG-LINK-PREREQS := $(common-dlib) $(api-serial-dlib) $(lld-dlib) $(aapl-avago-dlib) $(aapl-avago-firmware-serdes) $(aapl-avago-firmware-sbus-master) $(aapl-avago-firmware-pcie) $(aapl-avago-firmware-hbm) $(aapl-avago-firmware-hbm-mbist)

$(PKG)-as-dependency := $($(PKG)-as-dependency) $(aapl-avago-dlib) $(aapl-avago-slib)

AVAGO_PREBUILT_DEPENDS ?= 0

ifeq ($(AVAGO_PREBUILT_DEPENDS), 1)
	PKG-SWIG-INCLUDE-FLAGS += -Ishared/include/aapl
	aapl-avago-configured-prereq :=
	aapl-avago-slib-src := prebuilt/lib_static/libAAPL.a
	aapl-avago-dlib-src := prebuilt/lib/libAAPL.so
	aapl-avago-firmware-serdes-dir := prebuilt/res
else
	PKG-SWIG-INCLUDE-FLAGS += -I$(aapl-avago-build-dir)/src/include
	aapl-avago-configured-prereq := externals/avago/$(aapl-ver).tar.gz $(PATCH_FILES)
	aapl-avago-slib-src := $(aapl-avago-build-dir)/src/.libs/libAAPL.a
	aapl-avago-dlib-src := $(aapl-avago-build-dir)/src/.libs/libAAPL.so
	aapl-avago-firmware-serdes-dir := externals/avago/
endif

ifeq ($(ARM_BUILD), 1)
	CONFIG_HOST := --host=arm-linux
endif

include $(MakefileTemplateRoot)/Makefile.module_targets

# Dependencies and flags for AAPL compilation
$(aapl-swig-wrap-src): $(aapl-avago-configured)

# Rules for the Avago AAPL library
aapl-avago-configured: $(aapl-avago-configured)

$(aapl-avago-firmware-serdes): $(aapl-avago-firmware-serdes-dir)/$(aapl-avago-firmware-serdes-file)
	$(SILENT)$(MKDIR) -p $(@D)
	$(SILENT)cp $< $@

$(aapl-avago-firmware-sbus-master): $(aapl-avago-firmware-serdes-dir)/$(aapl-avago-firmware-sbus-master-file)
	$(SILENT)$(MKDIR) -p $(@D)
	$(SILENT)cp $< $@


$(aapl-avago-firmware-pcie): $(aapl-avago-firmware-serdes-dir)/$(aapl-avago-firmware-pcie-file)
	$(SILENT)$(MKDIR) -p $(@D)
	$(SILENT)cp $< $@

$(aapl-avago-firmware-hbm): $(aapl-avago-firmware-serdes-dir)/$(aapl-avago-firmware-hbm-file)
	$(SILENT)$(MKDIR) -p $(@D)
	$(SILENT)cp $< $@

$(aapl-avago-firmware-hbm-mbist): $(aapl-avago-firmware-serdes-dir)/$(aapl-avago-firmware-hbm-mbist-file)
	$(SILENT)$(MKDIR) -p $(@D)
	$(SILENT)cp $< $@

$(aapl-avago-configured): $(aapl-avago-configured-prereq)
	$(SILENT)echo Configuring the Avago AAPL library...
ifeq ($(AVAGO_PREBUILT_DEPENDS), 1)
	$(SILENT)$(MKDIR) -p $(@D)
else
	$(SILENT)$(RM) -rf $(@D)
	$(SILENT)$(MKDIR) -p $(@D)
	$(SILENT)tar zxf externals/avago/$(aapl-ver).tar.gz -C $(aapl-build-dir)
	$(foreach pfile,$(PATCH_FILES), patch -p0 -d $(aapl-avago-build-dir)/src < $(pfile);)
	$(SILENT)cd $(aapl-avago-build-dir) ; env CC="$(GCC)" CXX="$(GXX)" CFLAGS=-D_GNU_SOURCE ./configure $(CONFIG_HOST)
endif
	$(SILENT)touch $@
	@echo Done configuring the Avago AAPL library.

$(aapl-avago-built): $(aapl-avago-configured)
ifeq ($(AVAGO_PREBUILT_DEPENDS), 0)
	$(SILENT)$(MAKE) SHELL= -C $(aapl-avago-build-dir)
endif
	$(SILENT)touch $@
	$(SILENT)echo Done building Avago AAPL library.

$(aapl-avago-build-dir)/src/.libs/libAAPL.a: $(aapl-avago-built)

$(aapl-avago-build-dir)/src/.libs/libAAPL.so: $(aapl-avago-built)

aapl-avago-slib: $(aapl-avago-slib)

$(aapl-avago-slib): $(aapl-avago-slib-src)
	$(SILENT)$(MKDIR) -p $(@D)
	$(SILENT)$(CP) $< $@

aapl-avago-dlib: $(aapl-avago-dlib)

$(aapl-avago-dlib): $(aapl-avago-dlib-src)
	$(SILENT)$(MKDIR) -p $(@D)
	$(SILENT)$(CP) $< $@

