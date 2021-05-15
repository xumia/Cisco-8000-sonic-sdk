# BEGIN_LEGAL
#
# Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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



PKG := test-hw-tables-ctm
PKG-TARGETS := swiglib test_py
PKG-PATH := shared/test/hw_tables/ctm

PKG-PY-TEST-PREREQS := $(test-hw-tables-prereqs) $(hw-tables-as-dependency) $(common-py-libs) $(test-hld-swig-dlib)

PKG-COMPILE-PREREQS := $(gtest-configured) $(hw-tables-as-dependency)
PKG-LINK-LIBS := -L$(DLIB_OUTPUT_DIR) -llld -ldevice_context -lcommon -lhw_tables $(gtest-slib) -lapi_serial -lrt -lpthread -lboost_iostreams -lz -ljansson
PKG-LINK-PREREQS := $(lld-dlib) $(device-context-dlib) $(common-dlib) $(hw-tables-dlib) $(gtest-slib) $(api-serial-dlib)
PKG-INCLUDE-FLAGS := -I$(ZLIB_INC_DIR) -Iinclude -I$(SHARED_BASE_ROOT)/include -I$(BASE_OUTPUT_DIR)/build/src -I$(BASE_OUTPUT_DIR)/build/shared/src -I$(SHARED_BASE_ROOT)/src/hw_tables -I../../externals/jansson
PKG-TEST-ARGS := random_seed=1234

PKG-SWIG-INCLUDE-FLAGS := -I$(SHARED_BASE_ROOT)/include -I$(BASE_OUTPUT_DIR)/build/shared/src -I$(cereal-include-path) -I$(SHARED_BASE_ROOT)/src/hw_tables
PKG-SWIG-COMPILE-PREREQS := $(test-hw-tables-ctm-prereqs)
PKG-SWIG-LINK-PREREQS := $(common-dlib) $(lld-dlib) $(device-context-dlib) $(lld-swig-dlib) $(api-serial-dlib) $(ra-dlib) $(hld-dlib)
PKG-SWIG-LINK-LIBS := -L$(DLIB_OUTPUT_DIR) -llld -ldevice_context -lcommon -lapi_serial -lrt -lz -lhw_tables -lra -lhld


PKG-PY-TEST-ENV := LD_LIBRARY_PATH=$(DLIB_OUTPUT_DIR) PYTHONPATH=shared/test/hw_tables/ctm:$(PYLIB_OUTPUT_DIR):$(ROOT_SCRIPT_DIR):shared/test/utils BASE_OUTPUT_DIR=$(BASE_OUTPUT_DIR)

include $(MakefileTemplateRoot)/Makefile.module_vars
include $(MakefileTemplateRoot)/Makefile.module_targets

