# BEGIN_LEGAL
#
# Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

export MakefileBaseRoot = $(abspath .)

export ROOT_SCRIPT_DIR = $(abspath ../scripts)
export ROOT_TOOLS_DIR = $(abspath ../tools)
export FORMAT_DIRS = src test
export MakefileTemplateRoot = $(abspath ../build)
export SDK_ROOT = $(abspath ..)
export ROOT_3RD_PARTY_PKGS_DIR = ../submodules/3rd-party/packages/

# Check for existence of directories, to handle single-asic source releases
ifneq ($(wildcard $(SDK_ROOT)/driver/pacific),)
    PROJECTS += pacific
endif

ifneq ($(wildcard $(SDK_ROOT)/driver/gibraltar),)
    PROJECTS += gibraltar
endif

DEVICE_TYPE ?= none

ifeq ($(DEVICE_TYPE), gibraltar)
    PROJECTS=${DEVICE_TYPE}
    export ASIC = GIBRALTAR_A0
    export ENABLE_SERIALIZATION ?= 1
else
    ifeq ($(DEVICE_TYPE), pacific)
        PROJECTS=${DEVICE_TYPE}
        # No support for serialization in Pacific
        export ENABLE_SERIALIZATION = 0
    else
        ifneq ($(DEVICE_TYPE), none)
            # Avoid user typos. Make sure that if DEVICE_TYPE was set, it has a value we support.
            $(error wrong device type ${DEVICE_TYPE})
        endif
    endif
endif

# makefile.top.pre check for existence of OUTROOT variable
# At first pass, if DEVICE_TYPE = none we will set it to wrong value, but it will never be used. On second pass we will get correct value
export OUTROOT = out/${DEVICE_TYPE}
ifneq ($(DEVICE_TYPE), none)
    SDK_OUTPUT_DIR ?= $(MakefileBaseRoot)/../driver/${DEVICE_TYPE}/out/$(BUILD_TYPE)
    export GTEST-BUILD-DIR ?= $(MakefileBaseRoot)/../driver/${DEVICE_TYPE}/out/$(BUILD_TYPE)/build/src/gtest/googletest-master/googletest/
    LEABA_DEFINED_FOLDER := $(MakefileBaseRoot)/../devices/${DEVICE_TYPE}/leaba_defined
endif

.PHONY: all
all: full

NPL_SRC_DIR := $(MakefileBaseRoot)/../npl/cisco_router
SDK_OUTPUT_DIR ?= ../driver/$(DEVICE_TYPE)/out/$(BUILD_TYPE)
SAI_BUILD_SRC_DIR ?= $(OUTROOT)/$(BUILD_TYPE)/build/src
LEABA_DEFINED_FOLDER := $(MakefileBaseRoot)/../devices/$(DEVICE_TYPE)/leaba_defined

# Generic defines
include $(MakefileTemplateRoot)/Makefile.top_pre

include $(MakefileTemplateRoot)/../tools/cereal_gen/Makefile.inc
include $(MakefileTemplateRoot)/../tools/cereal/Makefile.inc

# Copy
include Makefile.copy_headers

include $(MakefileBaseRoot)/src/Makefile.inc
include $(MakefileBaseRoot)/test/gtest/Makefile.inc
include $(MakefileBaseRoot)/test/python/Makefile.inc

# Generic targets
include $(MakefileTemplateRoot)/Makefile.top_targets


gibraltar-lib-names := apb api_serial cadence common cpu2jtag device_simulator_client hld hw_tables jansson lld nplapi nsim_provider ra srm vendorsrm
gibraltar-slibs := $(foreach name, $(gibraltar-lib-names), $(BUILD_OUTPUT_DIR)/sdk/lib$(name).o )

TEST_PROJECTS = $(foreach project, $(PROJECTS), $(project)-test)
.PHONY: test $(TEST_PROJECTS)
test: $(TEST_PROJECTS)
$(TEST_PROJECTS): %-test:
	$(MAKE) DEVICE_TYPE=$* sai_test-test-py

SANITY_PROJECTS = $(foreach project, $(PROJECTS), $(project)-sanity)
.PHONY: sanity $(SANITY_PROJECTS)
sanity: $(SANITY_PROJECTS)
$(SANITY_PROJECTS): %-sanity:
	$(MAKE) DEVICE_TYPE=$* sai_gtest sai_test-test-py

GTEST_PROJECTS = $(foreach project, $(PROJECTS), $(project)-gtest)
.PHONY: gtest-all $(GTEST_PROJECTS)
gtest: $(GTEST_PROJECTS)
$(GTEST_PROJECTS): %-gtest:
	$(MAKE) DEVICE_TYPE=$* sai_gtest

# Note: We could be single-compile if we didn't need to look into driver out/ for la_event.h
ifeq ($(DEVICE_TYPE), pacific)
        PROJECTS = pacific
endif
ifeq ($(DEVICE_TYPE), gibraltar)
        PROJECTS = gibraltar
endif

SRC_PROJECTS = $(foreach project, $(PROJECTS), $(project)-src)
.PHONY: src $(SRC_PROJECTS)
src: $(SRC_PROJECTS)
$(SRC_PROJECTS): %-src:
	$(MAKE) DEVICE_TYPE=$* sai


#  Rules to build a full static library for the entire SDK, including SAI.
#
#  Various libraries have objects which rely on static initialization for
#  polymorphic registration. Therefore, they have no clear entry point from the
#  rest of the application. In order to prevent the final link from excluding
#  these, first do a first round of partial linking into .o's per library, using
#  --whole-archive option, then package that up into a .a
#
#  We do not do a complete partial link of everything into a single .o, since
#  with debug symbols enabled, that may cause the archive member size to exceed
#  4G. This causes problems with some linkers.

FULL_PROJECTS = $(foreach project, $(PROJECTS), $(project)-full)
.PHONY: full $(FULL_PROJECTS)
full: $(FULL_PROJECTS)
$(FULL_PROJECTS): %-full:
	$(MAKE) DEVICE_TYPE=$* sai
	$(MAKE) DEVICE_TYPE=$* full-slib

$($(DEVICE_TYPE)-slibs): $(BUILD_OUTPUT_DIR)/sdk/%.o : $(SDK_OUTPUT_DIR)/lib_static/%.a
	$(SILENT)$(MKDIR) -p $(@D)
	$(LD) -r -o $@ --whole-archive $^

$(BUILD_OUTPUT_DIR)/libsai.o : $(SLIB_OUTPUT_DIR)/libsai.a
	$(LD) -r -o $@ --whole-archive $^

FULL_SLIB = $(SLIB_OUTPUT_DIR)/libsai_full.a
.PHONY: full-slib
full-slib: $(FULL_SLIB)

$(FULL_SLIB): $($(DEVICE_TYPE)-slibs) $(BUILD_OUTPUT_DIR)/libsai.o
	$(RM) -f $@
	$(AR) r $@ $^

.PHONY: clean
clean::
	@echo clean
	rm -rf out
	rm -f src/auto_tostrings.cpp
