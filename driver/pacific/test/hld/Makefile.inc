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

test-hld-prereqs := | $(firmware-cem-as-dependency) $(cpu2jtag-as-dependency) api api-include $(hld-swig-dlib)
test-hld-includes := -I$(INCLUDE_OUTPUT_DIR) -Isrc/hld -I$(BOOST_INC_DIR) -I$(BASE_OUTPUT_DIR)/build/src/ -I$(BASE_OUTPUT_DIR)/build/shared/src -I../shared/src/hld -Ishared/src/hld -Ishared/include
test-hld-link-libs := -L$(DLIB_OUTPUT_DIR) -lhld -lz

PKG := test-hld
PKG-TARGETS := swiglib test_py
PKG-PATH := test/hld

PKG-SWIG-COMPILE-PREREQS := $(test-hld-prereqs)
PKG-SWIG-INCLUDE-FLAGS := $(test-hld-includes) -I$(BASE_OUTPUT_DIR)/build/src/hld
PKG-SWIG-LINK-PREREQS := $(hld-dlib) $(api-serial-dlib) $(nplapi-swig-dlib) $(test-nsim-provider-swig-dlib) $(test-ra-swig-dlib) $(test-rtl-swig-dlib) $(test-lld-swig-dlib) $(hw-tables-swig-dlib)
PKG-SWIG-LINK-LIBS :=  $(test-hld-link-libs)

PKG-PY-TEST-ENV := $(NSIM_RUN_ARGS) LD_LIBRARY_PATH=$(DLIB_OUTPUT_DIR) PYTHONPATH=shared/src/common:test/hld:shared/test/api:$(PYLIB_OUTPUT_DIR):shared/test/utils BASE_OUTPUT_DIR=$(BASE_OUTPUT_DIR)
PKG-PY-TEST-PREREQS := $(test-lld-swig-dlib)

include $(MakefileTemplateRoot)/Makefile.module_vars
include $(MakefileTemplateRoot)/Makefile.module_targets

