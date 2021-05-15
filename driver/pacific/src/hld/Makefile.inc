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

hld-prereqs := $(nplapi-configured) $(lld-lbrs-configured) | api-include aapl
hld-includes :=  -I$(INCLUDE_OUTPUT_DIR) -I$(SHARED_INCLUDE_OUTPUT_DIR) -Isrc/hld -Ishared/src/hld -I$(BASE_OUTPUT_DIR)/build/src -I$(BASE_OUTPUT_DIR)/build/shared/src \
-I$(BOOST_INC_DIR) -DVERSION=$(VERSION) -Ishared/externals/jansson
hld-link-libs-prereqs :=  $(common-dlib) $(lld-dlib) $(device-context-dlib) $(nplapi-dlib) $(nsim-provider-dlib) $(aapl-avago-dlib) $(hw-tables-dlib) $(jansson-dlib)  $(ra-dlib) $(device_simulator_client-slib) $(cpu2jtag-dlib)
hld-link-libs := -L$(DLIB_OUTPUT_DIR) -lcommon -llld -lnplapi -lnsim_provider -lAAPL -lhw_tables -l jansson -lra $(device_simulator_client-slib) -lcpu2jtag -ldevice_context

PKG := hld
PKG-TARGETS := libs swiglib
PKG-PATH := src/hld
PKG-SUBDIRS := npu system tm qos cgm
PKG-GENERATED-CPP-FILES := resolution_macro_cfg.cpp

# Multi-device migration
#
# By default only *_base.cpp and *_<device>.cpp are captured here, other files
# are omitted.  Add more files to this variable as needed.
#
PKG-EXTRA_CPPSRCS := \
    $(wildcard shared/src/hld/*_base.cpp) \
    $(wildcard shared/src/hld/*_pacific.cpp) \
    $(foreach subdir, $(PKG-SUBDIRS), $(wildcard shared/src/hld/$(subdir)/*_base.cpp)) \
    $(foreach subdir, $(PKG-SUBDIRS), $(wildcard shared/src/hld/$(subdir)/*_ifg.cpp)) \
    $(foreach subdir, $(PKG-SUBDIRS), $(wildcard shared/src/hld/$(subdir)/*_pacgb.cpp)) \
    $(foreach subdir, $(PKG-SUBDIRS), $(wildcard shared/src/hld/$(subdir)/*_pacific.cpp))

PKG-COMPILE-PREREQS := $(hld-prereqs)
PKG-INCLUDE-FLAGS := -I$(ZLIB_INC_DIR) $(hld-includes)
PKG-LINK-PREREQS := $(hld-link-libs-prereqs)
PKG-LINK-LIBS := $(hld-link-libs) -lrt -lz

PKG-PY-MODULE-PATH := leaba
PKG-SWIG-COMPILE-PREREQS := $(hld-prereqs)
PKG-SWIG-INCLUDE-FLAGS := $(hld-includes) -I$(BASE_OUTPUT_DIR)/build/src/hld -I$(SHARED_BASE_ROOT)
PKG-SWIG-LINK-PREREQS := $(hld-link-libs-prereqs)
PKG-SWIG-LINK-LIBS := $(hld-link-libs) -lz

UDK-SRC-PREREQS := runtime_flexibility_library.cpp runtime_flexibility_resources.cpp runtime_flexibility_types.cpp
UDK-HDR-PREREQS := runtime_flexibility_library.h runtime_flexibility_types.h runtime_flexibility_resources.h

PKG-GENERATED-CPP-FILES += $(UDK-SRC-PREREQS)
PKG-GENERATED-H-FILES += $(UDK-HDR-PREREQS)

PKG-CEREAL-GEN := True
PKG-CEREAL-EXTRA-DIRS := shared/src/hld
PKG-CEREAL-PREREQS := $(hld-prereqs)
PKG-CEREAL-CONFIG-FILE := serialize_config.cfg

include $(MakefileTemplateRoot)/Makefile.module_vars

# adding shared/src/hld before we include Makefile.module_vars will add all the h files from it to the serialization.
# Since not all h files are needed from shared/src/hld, we add those files and folder only after Makefile.module_vars is included
$(PKG)-cereal-module-dirs += shared/src/hld \
    $(patsubst %,shared/src/hld/%, $(PKG-SUBDIRS))

$(PKG)-cereal-h-files += \
    $(wildcard shared/src/hld/*_base.h) \
    $(wildcard shared/src/hld/*_pacific.h) \
    $(foreach subdir, $(PKG-SUBDIRS), $(wildcard shared/src/hld/$(subdir)/*_base.h)) \
    $(foreach subdir, $(PKG-SUBDIRS), $(wildcard shared/src/hld/$(subdir)/*_ifg.h)) \
    $(foreach subdir, $(PKG-SUBDIRS), $(wildcard shared/src/hld/$(subdir)/*_pacgb.h)) \
    $(foreach subdir, $(PKG-SUBDIRS), $(wildcard shared/src/hld/$(subdir)/*_pacific.h))

prebuild-dir := prebuilt/build/shared/src/nplapi

ifeq ($(PREBUILT_AND_NO_NPL), 1)
	UDK-PATH-BASE := $(prebuild-dir)
else
	UDK-PATH-BASE := $(nplapi-build-dir)
endif

UDK-PATH-HEADERS-FROM := $(UDK-PATH-BASE)/compiled/api/include/runtime_flexibility
UDK-PATH-SRCS-FROM := $(UDK-PATH-BASE)/compiled/api/src/runtime_flexibility
UDK-PATH-HEADERS-TO := $(hld-build-dir)
UDK-PATH-SRCS-TO := $(hld-build-dir)
# Fully Qualified Destination
# Notice, changing any of these two rules requires fixing the corresponding copying rules below
UDK-FQ-SRC-PREREQS := $(addprefix $(UDK-PATH-SRCS-TO)/, $(UDK-SRC-PREREQS))
UDK-FQ-HDR-PREREQS := $(addprefix $(UDK-PATH-HEADERS-TO)/, $(UDK-HDR-PREREQS))


# Fully Qualified Source for the sources and headers
UDK-FQ-FROM-SRC-PREREQS := $(addprefix $(UDK-PATH-SRCS-FROM)/, $(UDK-SRC-PREREQS))
UDK-FQ-FROM-HDR-PREREQS := $(addprefix $(UDK-PATH-HEADERS-FROM)/, $(UDK-HDR-PREREQS))

# We create the folders. Sort used for dealing with same folder case.
$(sort $(UDK-PATH-HEADERS-TO) $(UDK-PATH-SRCS-TO)):
	$(SILENT)$(MKDIR) -p $@

# Make the source of the UDK include and source files dependent on the module nplapi
$(UDK-FQ-FROM-SRC-PREREQS) $(UDK-FQ-FROM-HDR-PREREQS): $(nplapi-configured)

$(UDK-FQ-HDR-PREREQS): $(UDK-PATH-HEADERS-TO)/% : $(UDK-PATH-HEADERS-FROM)/% | $(UDK-PATH-HEADERS-TO)
	$(SILENT)$(CP) $< $@

# Triggered by PKG-GENERATED-CPP-FILES
$(UDK-FQ-SRC-PREREQS): $(UDK-PATH-SRCS-TO)/% : $(UDK-PATH-SRCS-FROM)/% | $(UDK-PATH-SRCS-TO)
	$(SILENT)$(CP) $< $@

PKG-COMPILE-PREREQS := $(UDK-FQ-HDR-PREREQS) $(PKG-COMPILE-PREREQS)
PKG-CEREAL-PREREQS := $(UDK-FQ-HDR-PREREQS) $(PKG-CEREAL-PREREQS)

include $(MakefileTemplateRoot)/Makefile.module_targets

# Auto generated files

hld-res-macro-cfg-tool = src/hld/autogen_decoding_config.py
hld-res-macro-cfg-input = $(NPL_SRC_DIR)/resolution/resolution_macro_types_cfg.sv

ifeq ($(PREBUILT_AND_NO_NPL), 1)
#$(hld-generated-cpp-files-path): $(hld-build-dir)/%: prebuilt/build/src/hld/%
$(hld-build-dir)/resolution_macro_cfg.cpp: $(hld-build-dir)/%: prebuilt/build/src/hld/%
	$(SILENT)$(MKDIR) -p $(@D)
	@echo Copy $@
	$(CP) $< $@
else
$(hld-build-dir)/$(PKG-GENERATED-CPP-FILES): $(hld-res-macro-cfg-input)
$(hld-build-dir)/$(PKG-GENERATED-CPP-FILES):
	$(SILENT)$(MKDIR) -p $(@D)
	@echo Generating $@
	$(SILENT)$(PYTHON_BIN) $(hld-res-macro-cfg-tool) $(hld-res-macro-cfg-input) $@
	@echo Done generating decoding config files.
endif

hld-generated-cpp-files: $(hld-build-dir)/$(PKG-GENERATED-CPP-FILES)

