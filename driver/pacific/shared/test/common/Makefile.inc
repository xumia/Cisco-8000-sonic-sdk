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

PKG := test-common
PKG-TARGETS := test_app
PKG-PATH := shared/test/common
PKG-COMPILE-PREREQS := $(gtest-configured)
PKG-LINK-LIBS := -lcommon -lapi_serial $(gtest-slib) -lrt -lz -lpthread
PKG-LINK-PREREQS := $(common-dlib) $(api-serial-dlib) $(gtest-slib)
PKG-INCLUDE-FLAGS := -I$(ZLIB_INC_DIR) -Iinclude -I$(SHARED_BASE_ROOT)/include -I$(BASE_OUTPUT_DIR)/build/src -I$(gtest-build-dir)/include

include $(MakefileTemplateRoot)/Makefile.module_vars
include $(MakefileTemplateRoot)/Makefile.module_targets

