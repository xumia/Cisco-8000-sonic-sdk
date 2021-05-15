# BEGIN_LEGAL
#
# Copyright (c) 2015-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

PKG := lld
PKG-TARGETS := libs swiglib
PKG-PATH := shared/src/lld
PKG-SUBDIRS := socket_connection

PKG-INCLUDE-FLAGS := -I$(ZLIB_INC_DIR) -I$(SHARED_BASE_ROOT)/include -I$(BASE_OUTPUT_DIR)/build/shared/src -I$(SHARED_BASE_ROOT)/include/lld/socket_connection -I../../externals/jansson
PKG-LINK-PREREQS := $(common-dlib) $(jansson-dlib) $(api-serial-dlib)
PKG-LINK-LIBS := -L$(DLIB_OUTPUT_DIR) -lcommon -ljansson -lapi_serial -lrt -lz

PKG-SWIG_EXTRA_SRCS :=
PKG-SWIG-INCLUDE-FLAGS := $(PKG-INCLUDE-FLAGS)
PKG-SWIG-LINK-PREREQS := $(PKG-LINK-PREREQS)
PKG-SWIG-LINK-LIBS := $(PKG-LINK-LIBS)

lld-src-dir = shared/src/lld/lbr_api_generator
lld-lbrs-configured := $(BASE_OUTPUT_DIR)/build/shared/src/$(PKG)/.lbrs-configured
ifeq ($(ENABLE_SERIALIZATION),1)
	PKG-COMPILE-PREREQS := $(lld-lbrs-configured) $(cereal-configured)
else
	PKG-COMPILE-PREREQS := $(lld-lbrs-configured)
endif
PKG-SWIG-COMPILE-PREREQS := $(PKG-COMPILE-PREREQS)

ASIC-LIST := gibraltar pacific
 ASIC-LIST-INT := gibraltar pacific

PKG-GENERATED-CPP-FILES := $(foreach asic, $(ASIC-LIST), $(asic)_tree.cpp)
PKG-GENERATED-H-FILES := $(foreach asic, $(ASIC-LIST), $(asic)_tree.h)
lld-lbrs-configured-asics := $(foreach asic, $(ASIC-LIST), $(lld-lbrs-configured).$(asic))

lld-interrupt-json-files = $(foreach asic, $(ASIC-LIST-INT), $(RES_OUTPUT_DIR)/$(asic)_interrupt_tree.json)


$(PKG)-as-dependency := $($(PKG)-as-dependency) $(lld-interrupt-json-files)

PKG-CEREAL-GEN := True
PKG-CEREAL-EXTRA-DIRS := shared/include/lld $(foreach subdir, $(PKG-SUBDIRS), shared/include/lld/$(subdir))
PKG-CEREAL-PREREQS := $(lld-lbrs-configured)
PKG-CEREAL-CONFIG-FILE := serialize_config.cfg

include $(MakefileTemplateRoot)/Makefile.module_vars
include $(MakefileTemplateRoot)/Makefile.module_targets

lld-generate-interrupt-tree-cmd := env PYTHONPATH=$(PYLIB_OUTPUT_DIR):$(SHARED_BASE_ROOT)/src/lld:$(SHARED_BASE_ROOT)/src/lld/lbr_api_generator LD_LIBRARY_PATH=$(PYLIB_OUTPUT_DIR) $(PYTHON_BIN) $(SHARED_BASE_ROOT)/src/lld/generate_interrupt_tree.py

ifeq ($(ARM_BUILD), 1)
RES_OUTPUT_DIR_NATIVE := $(strip $(subst $(ARM_SUFIX),,$(RES_OUTPUT_DIR)))
$(lld-interrupt-json-files): $(RES_OUTPUT_DIR)/%_interrupt_tree.json: $(lld-swig-dlib)
	@echo Copying $@ from $(strip $(subst $(ARM_SUFIX),,$@))
	$(CP) -r $(strip $(subst $(ARM_SUFIX),,$@)) $@
else
$(lld-interrupt-json-files): $(RES_OUTPUT_DIR)/%_interrupt_tree.json: $(lld-swig-dlib)
	@echo Creating $@
	$(SILENT)$(lld-generate-interrupt-tree-cmd) --asic=$(subst _interrupt_tree,,$(*F)) --lbr=$(subst _interrupt,,$@) --out=$@
endif

# Add the following define only when building LLD to be used through VCS simulation
# CXXFLAGS += -DLEABA_SIMULATION_CFG

lld-npsuite-lbr-validate := $(RES_OUTPUT_DIR)/$(ASIC_NAME)/hw_definitions/.npsuite_lbr_compare_success

$(lld-lbrs-configured): $(lld-lbrs-configured-asics) $(lld-npsuite-lbr-validate)
	@touch $@

$(lld-lbrs-configured-asics): $(lld-lbrs-configured).%:
	$(SILENT)$(MAKE) lld-build-dir=$(lld-build-dir) lld-src-dir=$(lld-src-dir) PYTHON_BIN=$(PYTHON_BIN) RES_OUTPUT_DIR=$(RES_OUTPUT_DIR) ASIC=$(subst $(lld-lbrs-configured).,,$@) -f $(lld-src-dir)/device_tree.make
	@touch $@

define compare
cmp -s $(1) $(2); \
RETVAL=$$?; \
if [ $$RETVAL -eq 0 ]; then \
		echo "$(3)"; \
else \
		echo "$(4)"; \
		diff -uNpr $(1) $(2) | head -20; \
	if [ $$PERMISSIVE -eq 1 ]; then \
			echo "WARRNING: PERMISSIVE=1 is set, ignoring npsuite_lbr.json validation failure!"; \
	else \
			exit -1; \
	fi \
fi
endef

GENERATED-NPSUITE-LBR-JSON := $(RES_OUTPUT_DIR)/$(ASIC_NAME)/hw_definitions/npsuite_lbr.json
COMMITED-NPSUITE-LBR-JSON := $(LEABA_DEFINED_FOLDER)/hw_definitions/npsuite_lbr.json

$(lld-npsuite-lbr-validate): $(lld-lbrs-configured-asics)
	$(SILENT)$(call compare, $(COMMITED-NPSUITE-LBR-JSON), $(GENERATED-NPSUITE-LBR-JSON),SUCCESS! No changes detected in $(COMMITED-NPSUITE-LBR-JSON), FAILURE! Generated file $(GENERATED-NPSUITE-LBR-JSON) differs from $(COMMITED-NPSUITE-LBR-JSON) which is commited! Please review update and commit!)
	@touch $@

# Creating shared library of socket connection for SV usage.

lld-conn-dlib := $(DLIB_OUTPUT_DIR)/liblld_conn$(DYNLIB_EXT)
$(lld-conn-dlib) : $(lld-dlib)
$(lld-conn-dlib) : LINK_LIBS_FLAGS :=
$(lld-conn-dlib) : OBJS := $(BASE_OUTPUT_DIR)/build/shared/src/lld/socket_connection/lld_conn_lib.o

lld-conn-dlib : $(lld-conn-dlib)

