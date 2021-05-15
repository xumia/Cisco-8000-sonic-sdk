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

include $(MakefileTemplateRoot)/Makefile.module_pre

PKG := test-lld
PKG-TARGETS := swiglib test_app test_py
PKG-PATH := shared/test/lld
PKG-COMPILE-PREREQS := $(gtest-configured) $(lld-as-dependency)
PKG-LINK-LIBS := -L$(DLIB_OUTPUT_DIR) -llld -lcommon -ljansson -lapi_serial $(gtest-slib) -lrt -lpthread -lz
PKG-LINK-PREREQS := $(lld-dlib) $(common-dlib) $(api-serial-dlib) $(gtest-slib) $(jansson-dlib)
PKG-INCLUDE-FLAGS := -I$(ZLIB_INC_DIR) -I$(SHARED_BASE_ROOT)/include -I$(BASE_OUTPUT_DIR)/build/src -I$(BASE_OUTPUT_DIR)/build/shared/src -I$(gtest-build-dir)/include -Ishared/src/lld -I$(cereal-include-path)

PKG-SWIG-INCLUDE-FLAGS := -I$(SHARED_BASE_ROOT)/include -Ishared/test/lld -I$(BASE_OUTPUT_DIR)/build/shared/src -I$(cereal-include-path)
PKG-SWIG-COMPILE-PREREQS := $(lld-lbrs-configured)
PKG-SWIG-LINK-LIBS := -L$(DLIB_OUTPUT_DIR) -ltest_lld -llld -lcommon -lapi_serial -lrt -lz
PKG-SWIG-LINK-PREREQS := $(common-dlib) $(lld-dlib) $(lld-swig-dlib) $(api-serial-dlib)
PKG-PY-TEST-ENV := $(NSIM_RUN_ARGS) LD_LIBRARY_PATH=$(DLIB_OUTPUT_DIR) PYTHONPATH=$(PYLIB_OUTPUT_DIR):shared/test/api:shared/test/utils

ifeq ($(ENABLE_SERIALIZATION), 1)
  PKG-SWIG-EXTRA-FLAGS += -DENABLE_SERIALIZATION
endif

include $(MakefileTemplateRoot)/Makefile.module_vars
include $(MakefileTemplateRoot)/Makefile.module_targets

