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

DEVICES_DIR ?= ../../devices
MKDIR ?= mkdir
CP ?= cp

include $(lld-src-dir)/$(ASIC)_device_tree.make

lld-src-lbrs-rev1-full := $(foreach l, $(lld-src-lbrs-rev1), $(lld-src-lbr-rev1-path)/$l)
lld-src-lbrs-rev2-full := $(foreach l, $(lld-src-lbrs-rev2), $(lld-src-lbr-rev2-path)/$l)

# add dummy LBR for simulators
lld-src-lbrs-rev2-full += $(lld-src-dir)/sim_translator.lbr

lld-sdk-block-uid := $(lld-src-block-info-path)/sdk_unit_id_defines.v
lld-src-lbrs-ovrd := $(lld-src-block-info-path)/lbr_overrides.json
lld-src-custom-blocks := $(lld-src-block-info-path)/custom_blocks_defines.json
lld-src-block-2-sw-path := $(lld-src-block-info-path)/block_to_sw_path.json
lld-sv-defines-path := $(lld-src-block-info-path)/sv_defines.py

# Generated list of relevant block IDs and addresses
lld-block-uid := $(lld-build-dir)/$(lld-device-name)-unit_id_defines.v

# Path to the code generation script
lld-lbr-tool := $(lld-src-dir)/lbr_api_generator.py

lld-lbr-json-file := $(RES_OUTPUT_DIR)/$(lld-device-name)_tree.json
lld-init-functions-file := $(RES_OUTPUT_DIR)/$(lld-device-name)_init_functions.h

lld-lbr-script-configured := $(lld-build-dir)/.$(lld-device-name)-lld-lbr-script-configured

all: $(lld-lbr-json-file) $(lld-init-functions-file) npsuite

$(lld-block-uid) : $(lld-design-block-uid) $(lld-sdk-block-uid)
	@$(MKDIR) -p $(@D)
	@echo Generating $@ from $<
	$(PYTHON_BIN) $(lld-src-dir)/update_unit_id_defines.py --design_defines $(lld-design-block-uid) --sdk_defines $(lld-sdk-block-uid) --output $@

$(lld-lbr-script-configured): $(lld-src-lbrs-rev1-full) $(lld-src-lbrs-rev2-full) $(lld-src-lbrs-ovrd) $(lld-block-uid) $(lld-src-custom-blocks) $(lld-src-block-2-sw-path) $(lld-sv-defines-path) $(lld-lbr-tool)
	@$(MKDIR) -p $(@D)
	@echo Generating $(lld-device-name) LBR headers at $(lld-build-dir)/$(lld-device-name)_*.{h,cpp}
	$(PYTHON_BIN) $(lld-lbr-tool) \
            $(foreach l, $(lld-src-lbrs-rev1-full), --lbr_rev1 $l) \
            $(foreach l, $(lld-src-lbrs-rev2-full), --lbr_rev2 $l) \
            --lbr_overrides $(lld-src-lbrs-ovrd) \
            --block_uid $(lld-block-uid) \
            --custom_block $(lld-src-custom-blocks) \
            --block_path $(lld-src-block-2-sw-path) \
            --sv_defines $(lld-sv-defines-path) \
            --sdk_init_functions_out $(lld-build-dir) \
            --verilog_default $(lld-verilog-default-path) \
            --base_address $(lld-base-address) \
            -o $(lld-build-dir)/$(lld-device-name)
	@touch $@
	@echo Done running $(lld-lbr-tool).

$(lld-lbr-json-file): $(lld-build-dir)/$(lld-device-name)_tree.json
	@$(MKDIR) -p $(@D)
	@$(CP) -v $^ $@

$(lld-init-functions-file): $(lld-build-dir)/$(lld-device-name)_init_functions.h
	@$(MKDIR) -p $(@D)
	@$(CP) -v $^ $@

$(lld-build-dir)/$(lld-device-name)_tree.json $(lld-build-dir)/$(lld-device-name)_init_functions.h : $(lld-lbr-script-configured)

npsuite-lbr-json-file := $(RES_OUTPUT_DIR)/$(lld-device-name)/hw_definitions/npsuite_lbr.json

npsuite: $(npsuite-lbr-json-file)

$(npsuite-lbr-json-file): $(lld-src-lbrs-rev1-full) $(lld-src-lbrs-rev2-full) $(lld-src-lbrs-ovrd) $(lld-block-uid) $(lld-src-custom-blocks) $(lld-src-block-2-sw-path) $(lld-lbr-tool)
	@$(MKDIR) -p $(@D)
	@echo Generating $(npsuite-lbr-json-file) at $(npsuite-lbr-json-file)
	$(PYTHON_BIN) $(lld-lbr-tool) \
		$(foreach l, $(lld-src-lbrs-rev1-full), --lbr_rev1 $l) \
        $(foreach l, $(lld-src-lbrs-rev2-full), --lbr_rev2 $l) \
        --lbr_overrides $(lld-src-lbrs-ovrd) \
        --block_uid $(lld-block-uid) \
        --custom_block $(lld-src-custom-blocks) \
        --block_path $(lld-src-block-2-sw-path) \
        --verilog_default $(lld-verilog-default-path) \
        --base_address $(lld-base-address) \
        --target 'npsuite' \
        -o $@
