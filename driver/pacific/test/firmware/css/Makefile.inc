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

ifndef MakefileTemplateRoot
$(error MakefileTemplateRoot is not set)
endif

ifndef MakefileBaseRoot
$(error MakefileBaseRoot is not set)
endif

#######################
# Grabbing settings from central Makefile
#######################

include $(MakefileTemplateRoot)/Makefile.module_pre

PKG 		:= test-firmware-css
PKG-TARGETS 	:= bin
PKG-PATH 	:= test/firmware/css

include $(MakefileTemplateRoot)/Makefile.module_vars

test-firmware-css-name := $(PKG-NAME)

########################
# Local staff
########################


FW_CSS_TEST_DIR		:= $(MakefileBaseRoot)/$(PKG-PATH)

# file lists
test-firmware-css-elf	:= $(MakefileBaseRoot)/$(BIN_OUTPUT_DIR)/$(test-firmware-css-name)_lib.elf
test-firmware-css-bin	:= $(MakefileBaseRoot)/$(BIN_OUTPUT_DIR)/$(test-firmware-css-name)_iccm.bin $(MakefileBaseRoot)/$(BIN_OUTPUT_DIR)/$(test-firmware-css-name)_iccm.hex  $(MakefileBaseRoot)/$(BIN_OUTPUT_DIR)/$(test-firmware-css-name)_dccm.bin $(MakefileBaseRoot)/$(BIN_OUTPUT_DIR)/$(test-firmware-css-name)_dccm.hex

#########################
# TARGETS
#########################

test-firmware-css: firmware-css-loader $(test-firmware-css-bin)

$(test-firmware-css-elf): FW_ELF_OBJ_DIR := $(MakefileBaseRoot)/$(test-firmware-css-build-dir)
$(test-firmware-css-elf): FW_ELF_CFLAGS	+= -I$(FW_CSS_SRC_DIR) -I$(FW_CSS_TEST_DIR)
$(test-firmware-css-elf): FW_ELF_TCF := $(FW_CSS_SRC_DIR)/hw/arc.css_pacific.mod.lib.tcf
$(test-firmware-css-elf): $(wildcard $(FW_CSS_SRC_DIR)/*.h) $(FW_CSS_TEST_DIR)/css_lib_test.cpp

$(test-firmware-css-bin): FW_ELF2HEX_BASE_ADDR := 0x1000_0000
$(test-firmware-css-bin): $(test-firmware-css-elf)

test-firmware-css-debug: test-firmware-css firmware-css-loader
	@$(FW_MW_DIR)/mdb -av2em -OK -project simple -tcf $(FW_CSS_SRC_DIR)/hw/arc.css_pacific.mod.tcf  -cmd="file2mem 0x0000_0604  $(MakefileBaseRoot)/$(BIN_OUTPUT_DIR)/$(test-firmware-css-name)_iccm.bin"  $(firmware-css-elf)

test-firmware-css-clean:
	@$(RM) -rf $(MakefileBaseRoot)/$(test-firmware-css-build-dir)
	@$(RM) -rf $(MakefileBaseRoot)/$(BIN_OUTPUT_DIR)/$(test-firmware-css-name)*

