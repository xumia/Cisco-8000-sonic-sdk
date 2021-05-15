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

ifeq ($(ENABLE_SERIALIZATION), 1)
sai-prereqs := | api-include $(cereal-gen-as-dependency) $(cereal-configured)
CFLAGS += -DENABLE_SERIALIZATION=1
else
sai-prereqs := | api-include $(cereal-gen-as-dependency)
endif

sai-includes := -I$(SDK_OUTPUT_DIR)/include -I$(INCLUDE_OUTPUT_DIR) -Isrc/ -I$(INCLUDE_OUTPUT_DIR)/sai -I../externals/jansson $(PYTHON_INC_FLAGS) -I$(cereal-include-path) -I$(LIBNL3_INC_DIR)
sai-link-libs = -ldl -L$(SDK_OUTPUT_DIR)/lib -lhld -lapi_serial -L$(LIBNL3_LINK_DIR) -lnl-genl-3 -lnl-3
CFLAGS += -DSAI_VERSION=$(sai-ver) -DCURRENT_SAI_VERSION_CODE=$(SAI_VER_CODE)
CXXFLAGS += -DSAI_VERSION=$(sai-ver) -DCURRENT_SAI_VERSION_CODE=$(SAI_VER_CODE)

PKG := sai
PKG-TARGETS := libs swiglib
PKG-PATH := src

api-sai-auto-gen-attr-file := $(BASE_OUTPUT_DIR)/build/src/auto_gen_attr.h
api-sai-auto-tostrings-file := $(BASE_OUTPUT_DIR)/build/src/auto_tostrings.cpp

PKG-COMPILE-PREREQS := $(sai-prereqs) $(api-sai-auto-gen-attr-file)
PKG-INCLUDE-FLAGS := $(sai-includes)
PKG-LINK-LIBS := -L$(DLIB_OUTPUT_DIR) $(sai-link-libs)

PKG-GENERATED-H-FILES := auto_gen_attr.h
PKG-GENERATED-CPP-FILES := auto_tostrings.cpp

PKG-SWIG-COMPILE-PREREQS := $(sai-prereqs)
PKG-SWIG-INCLUDE-FLAGS := $(sai-includes) -DCURRENT_SAI_VERSION_CODE=$(SAI_VER_CODE)
PKG-SWIG-LINK-LIBS := -L$(DLIB_OUTPUT_DIR) $(sai-link-libs)

PKG-CEREAL-NUM-OF-GENERATED-FILES := 32
PKG-CEREAL-GEN := True
PKG-CEREAL-CONFIG-FILE := serialize_config.cfg

include $(MakefileTemplateRoot)/Makefile.module_vars
$(PKG)-cereal-module-dirs += $(INCLUDE_OUTPUT_DIR)/sai/
include $(MakefileTemplateRoot)/Makefile.module_targets

$(api-sai-auto-gen-attr-file): src/auto_gen_attr.h_$(SAI_VER_SUFFIX)
	@$(MKDIR) -p $(BASE_OUTPUT_DIR)/build/src
	@echo copying SAI auto_gen_attr.h version $(SAI_VER_SUFFIX) $(SAI_VER_CODE)
	@$(CP) $^ $@

$(api-sai-auto-tostrings-file): src/auto_tostrings.cpp_$(SAI_VER_SUFFIX)
	@$(MKDIR) -p $(BASE_OUTPUT_DIR)/build/src
	@echo copying SAI auto_tostrings.cpp version $(SAI_VER_SUFFIX) $(SAI_VER_CODE)
	@$(CP) $^ $@
