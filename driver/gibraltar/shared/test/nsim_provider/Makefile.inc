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

prebuild-dir := prebuilt/build/shared/src/nplapi
test-nsim-prereqs := $(lld-lbrs-configured) $(nplapi-configured)

ifeq ($(PREBUILT_AND_NO_NSIM), 1)
	test-nsim-includes := -I$(SHARED_BASE_ROOT)/include -I$(prebuild-dir)/compiled/api/include -Iprebuilt/build/shared/src -I$(BASE_OUTPUT_DIR)/build/src -I$(BASE_OUTPUT_DIR)/build/shared/src -I$(NSIM_INC_DIR)
else
	test-nsim-includes := -I$(SHARED_BASE_ROOT)/include -I$(nplapi-build-dir)/compiled/api/include -I$(BASE_OUTPUT_DIR)/build/src -I$(BASE_OUTPUT_DIR)/build/shared/src -I$(NSIM_INC_DIR)
endif
test-nsim-link-libs-prereqs := $(common-dlib) $(api-serial-dlib) $(lld-dlib) $(nplapi-dlib) $(nsim-provider-dlib) $(device_simulator_client-slib)
test-nsim-link-libs := -L$(DLIB_OUTPUT_DIR) -lcommon -lapi_serial -llld -lnplapi -lnsim_provider $(device_simulator_client-slib)

PKG := test-nsim-provider
PKG-TARGETS := libs swiglib
PKG-PATH := shared/test/nsim_provider

PKG-COMPILE-PREREQS := $(test-nsim-prereqs)
PKG-INCLUDE-FLAGS := -I$(ZLIB_INC_DIR) $(test-nsim-includes)
PKG-LINK-PREREQS := $(test-nsim-link-libs-prereqs)
PKG-LINK-LIBS := $(test-nsim-link-libs) -lz

PKG-SWIG-COMPILE-PREREQS := $(test-nsim-prereqs)
PKG-SWIG-INCLUDE-FLAGS := $(test-nsim-includes)
ifeq ($(SIMULATOR), 1)
    PKG-SWIG-INCLUDE-FLAGS += -DSIMULATOR
endif
PKG-SWIG-LINK-PREREQS := $(test-nsim-link-libs-prereqs)
PKG-SWIG-LINK-LIBS := $(test-nsim-link-libs) -lz

include $(MakefileTemplateRoot)/Makefile.module_vars
include $(MakefileTemplateRoot)/Makefile.module_targets
