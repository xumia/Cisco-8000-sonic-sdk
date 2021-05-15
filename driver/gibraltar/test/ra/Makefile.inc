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

prebuild-dir := prebuilt/build/shared/src/nplapi
test-ra-prereqs := $(ra-configured) $(nplapi-configured) $(lld-lbrs-configured)

ifeq ($(PREBUILT_AND_NO_NPL), 1)
	test-ra-includes := -I$(SHARED_BASE_ROOT)/include -Isrc/ra -Itest/ra -I$(BASE_OUTPUT_DIR)/build/src -I$(BASE_OUTPUT_DIR)/build/shared/src -I$(prebuild-dir)/compiled/api/include -I$(SHARED_BASE_ROOT)/src/hw_tables
else
	test-ra-includes := -I$(SHARED_BASE_ROOT)/include -Isrc/ra -Itest/ra -I$(BASE_OUTPUT_DIR)/build/src -I$(BASE_OUTPUT_DIR)/build/shared/src -I$(nplapi-build-dir)/compiled/api/include -I$(SHARED_BASE_ROOT)/src/hw_tables
endif
test-ra-link-libs := -L$(DLIB_OUTPUT_DIR) -llld -lhw_tables -lra -llld_conn -lcommon -lapi_serial -lz -ldevice_context

PKG := test-ra
PKG-TARGETS := libs swiglib
PKG-PATH := test/ra
PKG-CXX-EXTRA-FLAGS := -Wno-array-bounds

PKG-COMPILE-PREREQS := $(test-ra-prereqs)
PKG-INCLUDE-FLAGS := -I$(ZLIB_INC_DIR) $(test-ra-includes)

PKG-SWIG-COMPILE-PREREQS := $(test-ra-prereqs)
PKG-SWIG-INCLUDE-FLAGS := $(test-ra-includes)
PKG-SWIG-LINK-PREREQS := $(ra-dlib) $(lld-conn-dlib) $(hw-tables-dlib) $(lld-dlib) $(device-context-dlib) $(api-serial-dlib)
PKG-SWIG-LINK-LIBS := $(test-ra-link-libs)

include $(MakefileTemplateRoot)/Makefile.module_vars
include $(MakefileTemplateRoot)/Makefile.module_targets

