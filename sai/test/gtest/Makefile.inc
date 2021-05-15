# BEGIN_LEGAL
#
# Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

PKG := sai_gtest
PKG-TARGETS := test_app
PKG-PATH := test/gtest
PKG-CXX-EXTRA-FLAGS := -Wno-array-bounds -Wno-maybe-uninitialized

PKG-COMPILE-PREREQS := sai
PKG-LINK-PREREQS := $(sai-dlib)
PKG-INCLUDE-FLAGS := -Iinclude -I$(BASE_OUTPUT_DIR)/include/sai -I$(SDK_OUTPUT_DIR)/include -I$(SDK_OUTPUT_DIR)/build/shared/src -I$(SDK_OUTPUT_DIR)/include/nsim_kernel -I$(NSIM_INC_DIR) -I$(GTEST-BUILD-DIR)/include
PKG-LINK-LIBS := -L$(NSIM_LIB_DIR)
PKG-LINK-LIBS += -Wl,-rpath-link,$(SDK_OUTPUT_DIR)/lib
PKG-LINK-LIBS += -L$(SDK_OUTPUT_DIR)/lib
PKG-LINK-LIBS += -lsai
PKG-LINK-LIBS += -lhld
PKG-LINK-LIBS += -lapi_serial
PKG-LINK-LIBS += $(SDK_OUTPUT_DIR)/lib_static/gtest_main.a
PKG-LINK-LIBS += -lrt
PKG-LINK-LIBS += -lpthread
PKG-LINK-LIBS += -lz
PKG-LINK-LIBS += -ldl
ifneq ($(NO_NSIM), 1)
	PKG-LINK-LIBS += -ltest_nsim_provider
    PKG-LINK-LIBS += -lnsim_kernel
endif
PKG-LINK-LIBS += $(PYTHON_LINK_FLAGS)

ifeq ($(ASIC), GIBRALTAR_A0)
    PKG-LINK-LIBS += -lvendorsrm
endif
ifeq ($(ASIC), GIBRALTAR_A1)
    PKG-LINK-LIBS += -lvendorsrm
endif

include $(MakefileTemplateRoot)/Makefile.module_vars
include $(MakefileTemplateRoot)/Makefile.module_targets

