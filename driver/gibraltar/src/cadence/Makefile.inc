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

PKG := cadence
PKG-TARGETS := libs swiglib
PKG-PATH := src/cadence

include $(MakefileTemplateRoot)/Makefile.module_vars

# General definitions

cadence-pci-build-dir := $(cadence-build-dir)/pci
cadence-pci-configured := $(cadence-pci-build-dir)/.configured
cadence-pci-built := $(cadence-pci-build-dir)/.built
cadence-pci-src-rep := externals/cadence/pci
cadence-pci-src-rep-files := $(wildcard $(cadence-pci-src-rep)/*.cpp) $(wildcard $(cadence-pci-src-rep)/*.h)
cadence-pci-src-dir := $(cadence-pci-build-dir)

cadence-pci-slib := $(SLIB_OUTPUT_DIR)/libcadencepci$(ARCHIVE_EXT)
cadence-pci-dlib := $(DLIB_OUTPUT_DIR)/libcadencepci$(DYNLIB_EXT)

PATCH_FILES = $(wildcard src/cadence/*.patch)
PKG-INCLUDE-FLAGS := -I$(cadence-pci-src-dir) -I$(SHARED_BASE_ROOT)/include
PKG-COMPILE-PREREQS := $(cadence-pci-configured)
PKG-LINK-PREREQS := $(common-dlib) $(apb-dlib) $(api-serial-dlib)
PKG-LINK-LIBS := -L$(DLIB_OUTPUT_DIR) -lcommon -lapb -lapi_serial
PKG-SWIG-INCLUDE-FLAGS := -I$(cadence-pci-src-dir) -I$(SHARED_BASE_ROOT)/include -I$(PKG-PATH)
PKG-SWIG-LINK-LIBS := -L$(DLIB_OUTPUT_DIR) -lcadencepci -lapb -lrt
PKG-SWIG-LINK-PREREQS := $(cadence-pci-dlib) $(apb-dlib)

$(PKG)-as-dependency := $($(PKG)-as-dependency) $(cadence-pci-dlib)

include $(MakefileTemplateRoot)/Makefile.module_targets

# Dependencies and flags for Cadence compilation
$(cadence-swig-wrap-src): $(cadence-pci-configured)

# Rules for the Cadence PCI library
cadence-pci-configured: $(cadence-pci-configured)

$(cadence-pci-configured): $(cadence-pci-src-rep-files)
	@echo Extracting Cadence SDK
	$(SILENT)$(RM) -rf $(@D)
	$(SILENT)$(MKDIR) -p $(@D)
	$(foreach sfile,$(cadence-pci-src-rep-files), cp $(sfile) $(@D);)
	$(SILENT)touch $@
	@echo Done configuring the Cadence library.

cadence-pci-built: $(cadence-pci-built)

$(cadence-pci-built): $(cadence-pci-configured)
	@echo Start building Cadence library.
	$(SILENT)cd $(cadence-pci-src-dir) && \
            $(CXX) $(CXXFLAGS) $(CXX_EXTRA_FLAGS) $(INCLUDE_FLAGS) \
                -I . -o libcadencepci.o -c torrent_api.cpp
	$(SILENT)cd $(cadence-pci-src-dir) && \
            $(CXX) $(CXXFLAGS) $(CXX_EXTRA_FLAGS) -shared \
                -o libcadencepci.so libcadencepci.o
	$(SILENT)cd $(cadence-pci-src-dir) && $(AR) $(AR_FLAGS) $(AR_OUTPUT_FLAG) libcadencepci.a libcadencepci.o
	$(SILENT)touch $@
	@echo Done building Cadence library.

cadence-pci-slib: $(cadence-pci-slib)

$(cadence-pci-src-dir)/libcadencepci.a: $(cadence-pci-built)

$(cadence-pci-slib): $(cadence-pci-src-dir)/libcadencepci.a
	$(SILENT)$(MKDIR) -p $(@D)
	$(SILENT)$(CP) $< $@

cadence-pci-dlib: $(cadence-pci-dlib)

$(cadence-pci-src-dir)/libcadencepci.so: $(cadence-pci-built)

$(cadence-pci-dlib): $(cadence-pci-src-dir)/libcadencepci.so
	$(SILENT)$(MKDIR) -p $(@D)
	$(SILENT)$(CP) $< $@

