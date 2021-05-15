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

PKG := hw-tables
PKG-TARGETS := libs swiglib
PKG-PATH := shared/src/hw_tables
PKG-SUBDIRS := ctm lpm em utils

prebuild-dir := prebuilt/build/shared/src/nplapi
ifeq ($(PREBUILT_DEPENDS), 1)
	PKG-INCLUDE-FLAGS := -I$(ZLIB_INC_DIR) -I$(BOOST_INC_DIR) -I$(SHARED_BASE_ROOT)/include -I$(BASE_OUTPUT_DIR)/build/shared/src -I$(BASE_OUTPUT_DIR)/build/src -I../../externals/jansson -I$(BASE_OUTPUT_DIR)/include -I$(prebuild-dir)/compiled/api/include
else
	PKG-INCLUDE-FLAGS := -I$(ZLIB_INC_DIR) -I$(BOOST_INC_DIR) -I$(SHARED_BASE_ROOT)/include -I$(BASE_OUTPUT_DIR)/build/shared/src -I$(BASE_OUTPUT_DIR)/build/src -I../../externals/jansson -I$(BASE_OUTPUT_DIR)/include -I$(nplapi-build-dir)/compiled/api/include
endif
PKG-COMPILE-PREREQS := $(lld-lbrs-configured) $(nplapi-configured)
PKG-LINK-LIBS := -L$(DLIB_OUTPUT_DIR) -lcommon -llld -lz -ljansson -lnplapi -lapi_serial -ldevice_context
PKG-LINK-PREREQS := $(common-dlib) $(lld-dlib) $(device-context-dlib) $(jansson-dlib) $(nplapi-dlib) $(api-serial-dlib)

PKG-SWIG-COMPILE-PREREQS := $(lld-lbrs-configured)
PKG-SWIG-INCLUDE-FLAGS := -I$(SHARED_BASE_ROOT)/include -I$(SHARED_BASE_ROOT)/src/hw_tables -I../../externals/jansson -I$(BOOST_INC_DIR)
PKG-SWIG-LINK-PREREQS := $(PKG-LINK-PREREQS) $(jansson-dlib)
PKG-SWIG-LINK-LIBS := $(PKG-LINK-LIBS)

PKG-CEREAL-GEN := True
PKG-CEREAL-EXTRA-DIRS := shared/include/hw_tables
PKG-CEREAL-CONFIG-FILE := serialize_config.cfg
PKG-CEREAL-PREREQS := $(lld-lbrs-configured) $(nplapi-configured)

include $(MakefileTemplateRoot)/Makefile.module_vars
include $(MakefileTemplateRoot)/Makefile.module_targets

