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

ifeq ($(NPSUITE_ROOT),)
    $(error NPSUITE_ROOT environment variable must be set and point to NPSuite release directory!)
endif

ifeq ($(wildcard $(NPSUITE_ROOT)),)
    $(error NPSUITE_ROOT=$(NPSUITE_ROOT) is pointing to invalid NPSuite location!)
endif

ifeq ($(NSIM_SOURCE_PATH),)
    $(error NSIM_SOURCE_PATH environment variable must be set and point to the NPL application source directory!)
endif

ifeq ($(wildcard $(NSIM_SOURCE_PATH)),)
    $(error NSIM_SOURCE_PATH=$(NSIM_SOURCE_PATH) is pointing to invalid location!)
endif

ifeq ($(NSIM_LEABA_DEFINED_FOLDER),)
    $(error NSIM_LEABA_DEFINED_FOLDER environment variable must be set and point to the device leaba_defined interface directory!)
endif

ifeq ($(wildcard $(NSIM_LEABA_DEFINED_FOLDER)),)
    $(error NSIM_LEABA_DEFINED_FOLDER=$(NSIM_LEABA_DEFINED_FOLDER) is pointing to invalid location!)
endif

$(info Using NPSUITE_ROOT = $(NPSUITE_ROOT))

export NSIM_INC_DIR ?= $(NPSUITE_ROOT)/include
export NSIM_LIB_DIR ?= $(NPSUITE_ROOT)/lib
export NSIM_RUN_ARGS ?= NPSUITE_ROOT=$(NPSUITE_ROOT) NSIM_SOURCE_PATH=$(NSIM_SOURCE_PATH) NSIM_LEABA_DEFINED_FOLDER=$(NSIM_LEABA_DEFINED_FOLDER)

# Parameter: Debug information build
export DEBUG ?= 1

# Parameter: Optimization level
export OPT ?= 0

GCC_DIR ?= /usr
CXX = $(GCC_DIR)/bin/g++
CXXFLAGS = -std=c++11 -gdwarf-2

OUTDIR ?= out

ifeq ($(OPT), 0)
    BUILD_TYPE = noopt
else
    BUILD_TYPE = opt$(OPT)
endif

ifeq ($(DEBUG), 1)
    BUILD_TYPE := $(BUILD_TYPE)-debug
endif

ifeq ($(ARM_BUILD), 1)
    BUILD_TYPE := $(BUILD_TYPE)-arm
endif

OUTDIR_BUILD_TYPE := $(OUTDIR)/$(BUILD_TYPE)

SRCS := $(filter-out example_system.cpp, $(wildcard *.cpp))
BINS := $(patsubst %.cpp, $(OUTDIR_BUILD_TYPE)/%, $(SRCS))

PYTHON_DIR ?= /usr

# additional python flags for compiling python extensions
PYTHON_CONFIG ?= $(PYTHON_DIR)/bin/python3-config
PYTHON_LINK_FLAGS := $(shell $(UNLOGGED) $(PYTHON_CONFIG) --ldflags)

.PRECIOUS: $(OUTDIR_BUILD_TYPE)/%
.PHONY: build-%

LINK_LIBS := -L../lib
LINK_LIBS += -ljansson
LINK_LIBS += -lcommon
LINK_LIBS += -lapi_serial
LINK_LIBS += -llld
LINK_LIBS += -ldevice_context
LINK_LIBS += -lcpu2jtag
LINK_LIBS += -lAAPL
LINK_LIBS += -lhw_tables
LINK_LIBS += -lnplapi
LINK_LIBS += -lra
LINK_LIBS += -lhld
LINK_LIBS += $(PYTHON_LINK_FLAGS)
LINK_LIBS += -lnsim_provider
ifneq ($(NO_NSIM), 1)
    LINK_LIBS += -ltest_nsim_provider
endif

$(OUTDIR_BUILD_TYPE)/%: %.cpp
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -I../include -I$(NSIM_INC_DIR) $(LINK_LIBS) -o $@ $< example_system.cpp

build-%: $(OUTDIR_BUILD_TYPE)/%
	@true

run-%: $(OUTDIR_BUILD_TYPE)/%
	env $(NSIM_RUN_ARGS) BASE_OUTPUT_DIR=../ LD_LIBRARY_PATH=../lib:$(GCC_DIR)/lib64 ./$<

build: $(BINS)

clean:
	rm -rf $(OUTDIR_BUILD_TYPE)

