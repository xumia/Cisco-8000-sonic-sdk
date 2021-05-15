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

include shared/src/nsim_provider/Makefile.dsim_client

include $(MakefileTemplateRoot)/Makefile.module_pre



PKG := nsim-provider
PKG-TARGETS := libs
PKG-PATH := shared/src/nsim_provider

nsim-provider-configured := $(BASE_OUTPUT_DIR)/build/$(PKG-PATH)/nsim_translator_creator_base.h
nsim-provider-prereqs := $(lld-lbrs-configured) $(nplapi-configured) $(nsim-provider-configured) | api-include

prebuild-dir := prebuilt/build/shared/src/nplapi

PKG-COMPILE-PREREQS :=  $(nsim-provider-prereqs)

ifeq ($(PREBUILT_AND_NO_NSIM), 1)
	PKG-INCLUDE-FLAGS := -I$(ZLIB_INC_DIR) -I$(SHARED_BASE_ROOT)/include -I$(prebuild-dir)/compiled/api/include -Iprebuilt/build/shared/src -I$(BASE_OUTPUT_DIR)/build/src -I$(BASE_OUTPUT_DIR)/build/shared/src -I$(NSIM_INC_DIR)
else
	PKG-INCLUDE-FLAGS := -I$(ZLIB_INC_DIR) -I$(SHARED_BASE_ROOT)/include -I$(nplapi-build-dir)/compiled/api/include -I$(BASE_OUTPUT_DIR)/build/src -I$(BASE_OUTPUT_DIR)/build/shared/src -I$(NSIM_INC_DIR)
endif

PKG-LINK-PREREQS := $(common-dlib) $(lld-dlib) $(nplapi-dlib) $(api-serial-dlib) $(device_simulator_client-slib)
PKG-LINK-LIBS := -L$(DLIB_OUTPUT_DIR) -lcommon -llld -lnplapi -lapi_serial -lz $(device_simulator_client-slib)

PKG-GENERATED-H-FILES := nsim_translator_creator_base.h
PKG-CEREAL-GEN := True
PKG-CEREAL-EXTRA-DIRS := shared/include/nsim_provider
PKG-CEREAL-PREREQS := $(nsim-provider-prereqs)
PKG-CEREAL-CONFIG-FILE := serialize_config.cfg

include $(MakefileTemplateRoot)/Makefile.module_vars
include $(MakefileTemplateRoot)/Makefile.module_targets

ifeq ($(PREBUILT_AND_NO_NSIM), 1)
$(nsim-provider-configured): $(nplapi-configured)
	@$(MKDIR) -p $(@D)
	@echo Generating NSIM translator creator at $(@D)
	$(CP) prebuilt/build/shared/src/nsim_provider/nsim_translator_creator_base.h $@
else
$(nsim-provider-configured): $(nplapi-configured)
	@$(MKDIR) -p $(@D)
	@echo Generating NSIM translator creator at $(@D)
	$(PYTHON_BIN) shared/src/nplapi/nplapi_translator_creator_generator.py --device $(if $(ASIC), $(ASIC), PACIFIC_B1) --output $@ --metadata_file $(nplapi-tables-json-file) --package simulator
endif

