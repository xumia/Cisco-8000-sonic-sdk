# BEGIN_LEGAL
#
# Copyright (c) 2015-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

export ASIC = GIBRALTAR_A1

export MakefileTemplateRoot = $(abspath ../../build)
export OUTROOT = out
export MakefileBaseRoot = $(abspath .)
export ASIC_NAME = $(notdir $(MakefileBaseRoot))
export SHARED_BASE_ROOT = $(abspath shared)
export NPL_BASE_ROOT = $(abspath ../../npl)
export ROOT_SCRIPT_DIR = ../../scripts
export ROOT_TOOLS_DIR = ../../tools
export ROOT_3RD_PARTY_PKGS_DIR = ../../submodules/3rd-party/packages
export FORMAT_DIRS = src test examples shared/src shared/include shared/test shared/scripts shared/manufacturing

# Build ARC firmware
BUILD_FIRMWARE ?= 0
JENKINS_SIM_RUN ?= 0

TEST_PKGS := test-kernel test-common test-lld test-cadence test-srm test-hw-tables-em test-hld test-api test-apb test-hw-tables-lpm test-hw-tables-ctm test-hw-tables-ctm-api test-debug
PKGS := apb cpu2jtag cadence srm esilicon hld lld hw-tables ra common nplapi jansson api api-serial firmware-cem debug

ifneq ($(BUILD_FIRMWARE), 0)
TEST_PKGS += test-firmware-cem
endif

.PHONY: all
all: src modules gtest
all: srm $(TEST_PKGS)

ifneq ($(GENERATE_DOCS), 0)
all: doc
endif

NPL_SRC_DIR ?= $(MakefileBaseRoot)/../../npl/cisco_router
LEABA_DEFINED_FOLDER ?= $(MakefileBaseRoot)/../../devices/gibraltar/leaba_defined

# Parameter: generate and compile automatic-generated code for serialization
ENABLE_SERIALIZATION ?= 1

# Generic defines
include $(MakefileTemplateRoot)/Makefile.top_pre

ifneq ($(PREBUILT_AND_NO_NSIM), 1)
all: nsim_kernel test-nsim-provider nsim-provider
endif

ifeq ($(PREBUILT_DEPENDS), 1)
    BUILD_FIRMWARE := 0
endif

# Driver specific defines
ifeq ($(DEBUG), 0)
    CFLAGS     += -DNDEBUG
    CXXFLAGS   += -DNDEBUG
endif

ifdef MATILDA_TEST_MODE
    export MATILDA_TEST_MODE_ENV = $(MATILDA_TEST_MODE)
endif

include ../../externals/jansson/Makefile.inc
include $(ROOT_TOOLS_DIR)/cereal/Makefile.inc
include $(ROOT_TOOLS_DIR)/cereal_gen/Makefile.inc
include $(SHARED_BASE_ROOT)/src/api/Makefile.api_serial.inc
include $(SHARED_BASE_ROOT)/src/common/Makefile.inc
include $(SHARED_BASE_ROOT)/src/lld/Makefile.inc
include $(SHARED_BASE_ROOT)/src/device_context/Makefile.inc
include $(SHARED_BASE_ROOT)/src/nplapi/Makefile.inc
include $(SHARED_BASE_ROOT)/src/cpu2jtag/Makefile.inc
include $(SHARED_BASE_ROOT)/src/apb/Makefile.inc
include $(SHARED_BASE_ROOT)/src/debug/Makefile.inc

include src/cadence/Makefile.inc
include src/srm/Makefile.inc
include src/esilicon/Makefile.inc
include $(SHARED_BASE_ROOT)/src/hw_tables/Makefile.inc
include src/ra/Makefile.inc

# Copy
include Makefile.copy_headers
include Makefile.copy_examples
include Makefile.copy_kernel_source
include $(SHARED_BASE_ROOT)/Makefile.copy_test

# Copy file with base SDK version to out dir if SDK is upgradeable
WB_BASE_SDK_VERSION_FILE = ../../wb_base_sdk_version.json
ifneq ($(wildcard $(WB_BASE_SDK_VERSION_FILE)),)
include $(SHARED_BASE_ROOT)/Makefile.copy_wb_base_sdk_version
all: copy-wb-base-sdk-version-file
endif

ifneq ($(BUILD_FIRMWARE), 0)
    ifeq ($(FW_MW_DIR),)
        $(error Firmware cannot be built without firmware tool-chain specified via $$FW_MW_DIR; use BUILD_FIRMWARE=0 to skip.)
    endif

    include src/firmware/Makefile.common.inc
    include src/firmware/cem/Makefile.inc
    include src/firmware/css/Makefile.inc
else
firmware-cem:
	cp prebuilt/res/firmware_cem* $(RES_OUTPUT_DIR)
endif

ifneq ($(PREBUILT_AND_NO_NSIM), 1)
    include $(SHARED_BASE_ROOT)/src/nsim_provider/Makefile.inc
    include $(SHARED_BASE_ROOT)/test/nsim_provider/Makefile.inc
    include src/nsim_kernel/Makefile.inc
else
    include $(SHARED_BASE_ROOT)/src/nsim_provider/dummy_nsim_provider/Makefile.inc
endif

include src/hld/Makefile.inc
include $(SHARED_BASE_ROOT)/src/api/Makefile.inc


include $(SHARED_BASE_ROOT)/test/gtest/Makefile.inc
include $(SHARED_BASE_ROOT)/test/common/Makefile.inc
include $(SHARED_BASE_ROOT)/test/lld/Makefile.inc
include $(SHARED_BASE_ROOT)/test/hw_tables/lpm/Makefile.inc
include $(SHARED_BASE_ROOT)/test/hw_tables/em/Makefile.inc
include $(SHARED_BASE_ROOT)/test/hw_tables/ctm/Makefile.inc
include $(SHARED_BASE_ROOT)/test/hw_tables/ctm_api/Makefile.inc
include test/ra/Makefile.inc
include test/hld/Makefile.inc
include $(SHARED_BASE_ROOT)/test/api/Makefile.inc
include test/sit/Makefile.inc
include $(SHARED_BASE_ROOT)/test/compat/Makefile.inc
include $(SHARED_BASE_ROOT)/test/apb/Makefile.inc
include test/cadence/Makefile.inc
include test/srm/Makefile.inc
include $(SHARED_BASE_ROOT)/test/kernel/Makefile.inc
include $(SHARED_BASE_ROOT)/test/debug/Makefile.inc

ifneq ($(BUILD_FIRMWARE), 0)
    include test/firmware/cem/Makefile.inc
    include test/firmware/css/Makefile.inc
    include test/firmware/screening/Makefile.inc
    test: test-firmware-cem-test
endif

include doc/Makefile.inc

# Generic targets
include $(MakefileTemplateRoot)/Makefile.top_targets

# Build examples
.PHONY: examples clean
examples: $(examples-copied) $(api) $(hld-dlib) $(vendor-srm-dlib) $(test-nsim-provider-dlib)
	@$(MAKE) -C $(BASE_OUTPUT_DIR)/examples GCC_DIR=$(GCC_DIR) $(NSIM_RUN_ARGS) PYTHON_DIR=$(PYTHON_DIR) build

# Copy tests
copy-test : $(tests-copied)

clean:: examples-clean modules-clean copy-test-clean

# Module targets
.PHONY: gtest
gtest: $(gtest-slib) $(gmock-slib)

# Test targets
.PHONY: test test-valgrind src sanity test-rtl

# TODO: in GB temporarily disable test-hld-test and test-sit-test, just enable compilation
#test:  test-common-test test-lld-test test-apb-test test-cadence-test test-hw-tables-lpm-test test-hw-tables-em-test test-hw-tables-ctm-test test-hld test-api-test examples
test: test-kernel test-common-test test-lld test-lld-test test-cadence-test test-srm-test test-hw-tables-em-test test-hw-tables-ctm-test test-hld test-api-test examples test-apb-test

ifeq ($(JENKINS_SIM_RUN), 0)
test: test-hw-tables-lpm-test
endif

# Benchmark for tests
.PHONY: benchmark benchmark-save
#benchmark: test-hw-tables-lpm-test-benchmark
#benchmark-save: test-hw-tables-lpm-test-benchmark-save

ifeq ($(PERMISSIVE), 0)
test: test-compat-test
endif

test-valgrind: test-common-test-valgrind test-apb-valgrind test-cadence-valgrin test-srm-valgrind test-hw-tables-em-test-valgrind test-hw-tables-ctm-test-valgrind #test-api-test-valgrind #test-hld-test-valgrind test-hw-tables-lpm-test-valgrind

test-warmboot: test-api-test-warmboot

test-warmboot-upgrade-rollback: test-api-test-warmboot-upgrade-rollback

test-dead-or-alive:	print-test-dead-or-alive test-api-test-dead-or-alive


showcov:
	@echo Cleaning gcov directory
	$(SILENT)$(RM) -rf $(COVERAGE_OUTPUT_DIR)/*
	$(SILENT)$(MKDIR) -p $(COVERAGE_OUTPUT_DIR)/html
	@echo Running gcov
	$(SILENT)$(GCOVR) -r . --exclude='.*/googletest.*' --exclude='/usr/include/.*' --html --html-details -o $(COVERAGE_OUTPUT_DIR)/html/coverage.html
	$(SILENT)$(GCOVR) -r . --exclude='.*/googletest.*' --exclude='/usr/include/.*' --xml-pretty -o $(COVERAGE_OUTPUT_DIR)/coverage.xml


src: $(PKGS) copy-test

sanity: src

ifneq ($(GENERATE_DOCS), 0)
sanity: doc-sanity
endif

# Source for external release (some 3rd-party should be precompiled)
ext-src: srm esilicon firmware-cem

# Source for external release (some 3rd-party should be precompiled)
customer-src: ra srm esilicon firmware-cem nsim-provider hld-generated-cpp-files

test-rtl: test-hld firmware-cem hw-tables

modules: modules-copy

modules-copy: leaba-module-copy

modules-clean: leaba-module-clean
