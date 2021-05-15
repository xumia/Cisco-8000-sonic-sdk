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

ra-database-resources-json-file := src/ra/database_resources_map.json
ra-microcode-json-filename := microcode_metadata_file.json
ra-microcode-json-file := $(RES_OUTPUT_DIR)/$(ra-microcode-json-filename)
ra-microcode-json-prebuild := prebuilt/res/$(ra-microcode-json-filename)

ifeq ($(PREBUILT_AND_NO_NPL), 1)
$(ra-microcode-json-file) : $(nplapi-configured)
	@$(MKDIR) -p $(@D)
	@echo "-RA- Merging NPL compiler output files"
	$(CP) $(ra-microcode-json-prebuild) $@
else
$(ra-microcode-json-file) : $(nplapi-configured)
	@$(MKDIR) -p $(@D)
	@echo "-RA- Merging NPL compiler output files"
	$(PYTHON_BIN) src/ra/npl_compiler_output_merge.py --microcode-dir $(nplapi-microcode-dir) --nplapi-tables $(nplapi-tables-json-file) --databases $(ra-database-resources-json-file) --output $@
endif

include $(MakefileTemplateRoot)/Makefile.module_pre

ra-configured := $(BASE_OUTPUT_DIR)/build/src/ra/ra_translator_creator_base.h
ra-prereqs := $(ra-configured) $(nplapi-configured) $(lld-lbrs-configured)
prebuild-dir := prebuilt/build/shared/src/nplapi

ifeq ($(PREBUILT_AND_NO_NPL), 1)
	ra-includes := -I$(SHARED_BASE_ROOT)/include -I$(BASE_OUTPUT_DIR)/build/src -I$(BASE_OUTPUT_DIR)/build/shared/src -Iprebuilt/build/shared/src -I$(prebuild-dir)/compiled/api/include -I../../externals/jansson -I$(SHARED_BASE_ROOT)/src/hw_tables -I$(BOOST_INC_DIR)
else
	ra-includes := -I$(SHARED_BASE_ROOT)/include -I$(BASE_OUTPUT_DIR)/build/src -I$(BASE_OUTPUT_DIR)/build/shared/src -I$(nplapi-build-dir)/compiled/api/include -I../../externals/jansson -I$(SHARED_BASE_ROOT)/src/hw_tables -I$(BOOST_INC_DIR)
endif

PKG := ra
PKG-TARGETS := libs
PKG-PATH := src/ra
PKG-SUBDIRS := special_tables

# JSON file is not actually needed for link. This is runtime dependency.
# Putting it here as a workaround to create dependency.

PKG-COMPILE-PREREQS := $(ra-prereqs)
PKG-INCLUDE-FLAGS := -I$(ZLIB_INC_DIR) $(ra-includes)
PKG-LINK-PREREQS := $(common-dlib) $(api-serial-dlib) $(lld-dlib) $(device-context-dlib) $(nplapi-dlib) $(hw-tables-dlib) $(jansson-dlib) $(ra-microcode-json-file)
PKG-LINK-LIBS :=  -L$(DLIB_OUTPUT_DIR) -lcommon -lapi_serial -llld -lnplapi -lhw_tables -ljansson -lrt -lz -ldevice_context

PKG-GENERATED-H-FILES := ra_translator_creator_base.h
PKG-CEREAL-GEN := True
PKG-CEREAL-EXTRA-DIRS := shared/include/ra $(foreach subdir, $(PKG-SUBDIRS), shared/include/ra/$(subdir))
PKG-CEREAL-PREREQS := $(ra-prereqs)
PKG-CEREAL-CONFIG-FILE := serialize_config.cfg

include $(MakefileTemplateRoot)/Makefile.module_vars
include $(MakefileTemplateRoot)/Makefile.module_targets

ra-configured: $(ra-configured)

ifeq ($(PREBUILT_AND_NO_NPL), 1)
$(ra-configured): $(nplapi-configured)
	@$(MKDIR) -p $(@D)
	@echo "Generating translator creator $@."
	$(CP) prebuilt/build/src/ra/ra_translator_creator_base.h $@
	@echo "Done generating."
else
$(ra-configured): $(nplapi-configured)
	@$(MKDIR) -p $(@D)
	@echo "Generating translator creator $@."
	$(PYTHON_BIN) $(SHARED_BASE_ROOT)/src/nplapi/nplapi_translator_creator_generator.py --device $(if $(ASIC), $(ASIC), PACIFIC_B1) --output $@  --metadata_file $(nplapi-tables-json-file) --package ra
	@echo "Done generating."
endif


