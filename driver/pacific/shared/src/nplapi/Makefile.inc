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

PKG := nplapi
PKG-TARGETS := py_lib libs swiglib
PKG-PATH := shared/src/nplapi
package-out-dir := $(BASE_OUTPUT_DIR)/build/$(PKG-PATH)
prebuild-dir := prebuilt/build/shared/src/nplapi
nplapi_cpp_files := npl_table_names.cpp npl_functional_table_traits.cpp npl_table_types.cpp npl_types.cpp npl_tables_static_init.cpp npl_enum_to_string.cpp la_event.cpp
translator_cpp_files := npl_table_entry_translation.cpp npl_generic_data_structs.cpp

nplapi_cpp_file_paths := $(foreach f, $(nplapi_cpp_files), compiled/api/src/nplapi/$(f))
translator_cpp_file_paths:= $(foreach f, $(translator_cpp_files), compiled/api/src/nplapi_translator/$(f))
PKG-GENERATED-CPP-FILES := $(nplapi_cpp_file_paths) $(translator_cpp_file_paths) device_tables.cpp

PKG-GENERATED-H-FILES :=\
	$(foreach f, npl_functional_table_traits.h npl_table_types.h npl_types.h npl_tables_static_init.h npl_enum_to_string.h la_event.h npl_constants.h npl_enums.h npl_tables_enum.h, compiled/api/include/nplapi/$(f)) \
	$(foreach f, npl_table_entry_translation.h npl_generic_data_structs.h, compiled/api/include/nplapi_translator/$(f)) \
	device_tables.h

nplapi-base-output-path := out/$(BUILD_TYPE)/build/shared/src/nplapi/compiled/api/src/nplapi
nplapi_cpp_full_file_paths := $(foreach f, $(nplapi_cpp_files), $(nplapi-base-output-path)/$(f))

translator-base-output-path := out/$(BUILD_TYPE)/build/shared/src/nplapi/compiled/api/src/nplapi_translator
translator_cpp_full_file_paths := $(foreach f, $(translator_cpp_files), $(translator-base-output-path)/$(f))

PKG-INCLUDE-FLAGS := -I$(ZLIB_INC_DIR) -I$(SHARED_BASE_ROOT)/include -I$(BASE_OUTPUT_DIR)/build/shared/src -I$(package-out-dir)/compiled/api/include -I$(SHARED_BASE_ROOT)/$(PKG-PATH)

ifeq ($(PREBUILT_AND_NO_NPL), 1)

$(nplapi_cpp_full_file_paths): $(nplapi-base-output-path)/%: $(prebuild-dir)/compiled/api/src/nplapi/% npl-microcode-configured
	$(MKDIR) -p $(@D)
	@echo Copy $@
	$(CP) $< $@

$(translator_cpp_full_file_paths): $(translator-base-output-path)/%: $(prebuild-dir)/compiled/api/src/nplapi_translator/% npl-microcode-configured
	$(MKDIR) -p $(@D)
	@echo Copy $@
	$(CP) $< $@

endif

ifeq ($(PREBUILT_AND_NO_NPL), 1)
PKG-SWIG-INCLUDE-FLAGS := $(PKG-INCLUDE-FLAGS) -I$(SHARED_BASE_ROOT) -Iprebuilt/build/shared/src
else
PKG-SWIG-INCLUDE-FLAGS := $(PKG-INCLUDE-FLAGS) -I$(SHARED_BASE_ROOT)
endif

#nplapi-configured := $(BASE_OUTPUT_DIR)/build/$(PKG-PATH)/.npl-configured
nplapi-configured := $(package-out-dir)/.npl-configured
#npl-microcode-configured := $(BASE_OUTPUT_DIR)/build/$(PKG-PATH)/.npl-microcode-configured
npl-microcode-configured := $(package-out-dir)/.npl-microcode-configured
nppd-fields-json-file-copy := $(RES_OUTPUT_DIR)/nppd_fields_types.json

prebuild-configured := $(prebuild-dir)/.npl-microcode-configured

nplapi-overrides-json-file := src/nplapi/allocations_overrides_file.json
ra-database-resources-json-file := src/ra/database_resources_map.json
device-tables-cpp :=  $(package-out-dir)/device_tables.cpp
device-tables-h :=  $(package-out-dir)/device_tables.h

ifneq ($(PREBUILT_AND_NO_NPL), 1)
PKG-COMPILE-PREREQS := $(nppd-fields-json-file-copy)
else
PKG-COMPILE-PREREQS := $(npl-microcode-configured)
endif

PKG-SWIG-COMPILE-PREREQS := $(PKG-COMPILE-PREREQS) $(device-tables-h)

PKG-CEREAL-GEN := True
PKG-CEREAL-CONFIG-FILE := serialize_config.cfg
PKG-CEREAL-PREREQS := $(PKG-COMPILE-PREREQS) $(device-tables-h)


PKG-LINK-PREREQS := $(common-dlib) $(api-serial-dlib)
PKG-LINK-LIBS := -L$(DLIB_OUTPUT_DIR) -lcommon -lapi_serial -lrt -lz
PKG-SWIG-LINK-PREREQS := $(PKG-LINK-PREREQS)
PKG-SWIG-LINK-LIBS := $(PKG-LINK-LIBS)

include $(MakefileTemplateRoot)/Makefile.module_vars

npl-archive := $(nplapi-build-dir)/compiled/$(NPSUITE_ARCHIVE_FILENAME)
ifneq ($(PREBUILT_AND_NO_NPL), 1)
ifeq ($(SIMULATOR), 1)
PKG-COMPILE-PREREQS += $(npl-archive)
endif
endif

include $(MakefileTemplateRoot)/Makefile.module_targets

NPL_SRC_FILES = $(call rwildcard, $(NPL_SRC_DIR), *.npl)

nplapi-tables-json-file := $(nplapi-build-dir)/compiled/api/json/npl_tables_locations.json
nplapi-microcode-dir := $(nplapi-build-dir)/compiled/microcode
nppd-fields-json-file := $(nplapi-build-dir)/compiled/sv_microcode/nppd_fields_types.json

nplapi-configured: $(nplapi-configured)
npl-microcode-configured: $(npl-microcode-configured)

-include $(wildcard $(nplapi-build-dir)/compiled/api/shared/src/nplapi/.deps/*.Td)

$(nplapi-configured): $(npl-microcode-configured) $(device-tables-cpp) $(device-tables-h)
	@touch $@

ifeq ($(PREBUILT_AND_NO_NPL), 1)
$(npl-microcode-configured): $(prebuild-configured)
	@$(MKDIR) -p $(@D)
	@$(MKDIR) -p $(RES_OUTPUT_DIR)
	@echo Copy NPLAPI from $(nplapi-build-dir)/api
	$(CP) -r $(prebuild-dir) $(@D)/..
	@$(MKDIR) -p $(RES_OUTPUT_DIR)
	$(CP) prebuilt/res/nppd_fields_types.json $(RES_OUTPUT_DIR)
	@touch $@
	@echo Done copy NPLAPI.
else

ifeq ($(ARM_BUILD), 1)
nplapi-build-dir-native := $(strip $(subst $(ARM_SUFIX),,$(nplapi-build-dir)))
$(npl-microcode-configured): $(lld-lbrs-configured)
	@$(MKDIR) -p $(@D)
	@echo Copying NPLAPI at from $(nplapi-build-dir-native) to $(nplapi-build-dir)
	$(CP) -r $(nplapi-build-dir-native)/* $(nplapi-build-dir)
	@touch $@
else
$(npl-microcode-configured): $(lld-lbrs-configured) $(NPL_SRC_FILES)
	@$(MKDIR) -p $(@D)
	@echo Generating NPLAPI at $(nplapi-build-dir)/api
ifeq ($(GENERATE_NPL), 1)
	env LD_PRELOAD=$(LD_PRELOAD_LIBS) LD_LIBRARY_PATH=$(GCC_DIR)/lib64:$(LD_LIBRARY_PATH) $(PYTHON_BIN) $(NPSUITE_ROOT)/bin/nplc.py --dump-preprocessed-files --folder $(NPL_SRC_DIR) --leaba_defined $(LEABA_DEFINED_FOLDER) --output $(nplapi-build-dir)/compiled --dump-parsed-items --gen-traps-report --gen-av-files --Wno-error-missing-traps-description --gen-logical-to-physical-file
	env LD_LIBRARY_PATH=$(GCC_DIR)/lib64:$(LD_LIBRARY_PATH) $(PYTHON_BIN) $(SHARED_BASE_ROOT)/src/nplapi/nplapi_table_list_generator.py --output $(nplapi-build-dir) --metadata_file $(nplapi-tables-json-file)
else
	@echo SKIP compiling NPL microcode
endif
	@echo "Deleting obsolete npsuite-generated header files..."
	$(RM) $(nplapi-build-dir)/compiled/api/include/nplapi/npl_tables.h
	$(RM) $(nplapi-build-dir)/compiled/api/include/nplapi/npl_table_translators_base.h
	@echo "Replacing bit_vector definition in the generated files..."
	@find $(nplapi-build-dir)/compiled -type f -exec sed -i 's/#include "utils\/nsim_bv.h"/#include "common\/bit_vector.h"\nusing silicon_one::bit_vector;\nusing silicon_one::bit_vector64_t;\nusing silicon_one::bit_vector128_t;\nusing silicon_one::bit_vector192_t;\nusing silicon_one::bit_vector384_t;/' {} +
	@touch $@
	@echo Done generating NPLAPI.
endif
ifeq ($(SIMULATOR), 1)
$(npl-archive): $(npl-microcode-configured)
	@echo Generating NPL archive for simulator release
	$(SILENT)$(MKDIR) -p $(@D)
	env LD_LIBRARY_PATH=$(GCC_DIR)/lib64:$(LD_LIBRARY_PATH) $(PYTHON_BIN) $(NPSUITE_ROOT)/bin/nplc.py --folder $(NPL_SRC_DIR) --leaba_defined $(LEABA_DEFINED_FOLDER) --create-nsim-archive  $@
endif
endif

$(nppd-fields-json-file-copy): $(npl-microcode-configured)
	$(SILENT)$(MKDIR) -p $(@D)
	$(SILENT)$(CP) $(nppd-fields-json-file) $(RES_OUTPUT_DIR)/

ifeq ($(PREBUILT_AND_NO_NPL), 1)
$(device-tables-h): npl-microcode-configured
$(device-tables-h): $(package-out-dir)/%.h: $(prebuild-dir)/%.h
	$(SILENT)$(MKDIR) -p $(@D)
	$(CP) $< $@

$(device-tables-cpp): npl-microcode-configured
$(device-tables-cpp): $(package-out-dir)/%.cpp: $(prebuild-dir)/%.cpp
	$(SILENT)$(MKDIR) -p $(@D)
	$(CP) $< $@

else
$(device-tables-cpp): $(device-tables-h) $(package-out-dir)/device_tables.dummy
$(device-tables-h):   $(package-out-dir)/device_tables.dummy
$(package-out-dir)/device_tables.dummy: $(nplapi-overrides-json-file) $(npl-microcode-configured) $(ra-database-resources-json-file)
	@echo "Generating device tables files creator $@."
	$(PYTHON_BIN) $(SHARED_BASE_ROOT)/src/nplapi/device_tables_generator.py --device $(if $(ASIC), $(ASIC), PACIFIC_B1) --databases $(ra-database-resources-json-file) --overrides_file $(nplapi-overrides-json-file) --nplapi_tables $(nplapi-tables-json-file) --output $(nplapi-build-dir)
	touch $(package-out-dir)/device_tables.dummy
	@echo "Done generating."
endif
