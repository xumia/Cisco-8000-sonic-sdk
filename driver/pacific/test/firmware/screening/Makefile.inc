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

PKG		:= test-firmware-screening
PKG-TARGETS	:= bin
PKG-PATH	:= test/firmware/screening

include $(MakefileTemplateRoot)/Makefile.module_vars

test-firmware-screening-name := $(PKG-NAME)

########################
# Local staff
########################


FW_AE_TEST_DIR		:= $(MakefileBaseRoot)/$(PKG-PATH)

# file lists
test-firmware-screening-elf	:= $(MakefileBaseRoot)/$(BIN_OUTPUT_DIR)/$(test-firmware-screening-name).elf
test-firmware-screening-bin	:= $(MakefileBaseRoot)/$(BIN_OUTPUT_DIR)/$(test-firmware-screening-name)_sys.bin $(MakefileBaseRoot)/$(BIN_OUTPUT_DIR)/$(test-firmware-screening-name)_sys.hex

#########################
# TARGETS
#########################

test-firmware-screening: $(test-firmware-screening-bin)

$(test-firmware-screening-elf): FW_ELF_OBJ_DIR := $(MakefileBaseRoot)/$(test-firmware-screening-build-dir)
$(test-firmware-screening-elf): FW_ELF_CFLAGS	+= -I$(FW_CSS_SRC_DIR) -I$(FW_AE_TEST_DIR)
$(test-firmware-screening-elf): FW_ELF_TCF := $(FW_CSS_SRC_DIR)/hw/arc.css_pacific.mod.tcf
$(test-firmware-screening-elf): $(wildcard $(FW_CSS_SRC_DIR)/*.h) $(FW_AE_TEST_DIR)/main_css.cpp $(FW_AE_TEST_DIR)/screening.cpp $(FW_AE_TEST_DIR)/spi_flash.cpp

$(test-firmware-screening-bin): FW_ELF2HEX_BASE_ADDR := 0x0000_0000
$(test-firmware-screening-bin): $(test-firmware-screening-elf)

test-firmware-screening-clean:
	@$(RM) -rf $(MakefileBaseRoot)/$(test-firmware-screening-build-dir)
	@$(RM) -rf $(MakefileBaseRoot)/$(BIN_OUTPUT_DIR)/$(test-firmware-screening-name)*

