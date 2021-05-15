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

ifndef SHARED_BASE_ROOT
$(error SHARED_BASE_ROOT is not set)
endif

ifndef MakefileBaseRoot
$(error MakefileBaseRoot is not set)
endif

#######################
# Grabbing settings from central Makefile
#######################

include $(MakefileTemplateRoot)/Makefile.module_pre

PKG 		:= firmware-cem
PKG-TARGETS 	:= bin
PKG-PATH 	:= src/firmware/cem

include $(MakefileTemplateRoot)/Makefile.module_vars


########################
# Local stuff
########################

FW_CEM_NAME             := $(PKG-NAME)

FW_CEM_SRC_DIR		:= $(MakefileBaseRoot)/$(PKG-PATH)
FW_CEM_SHARED_SRC_DIR   := $(MakefileBaseRoot)/shared/src/firmware/cem
FW_CEM_BIN_DIR          := $(RES_OUTPUT_DIR)
FW_CEM_OBJ_DIR          := $(MakefileBaseRoot)/$(firmware-cem-build-dir)

########################
# File lists
########################

FW_CEM_ELF   := $(FW_CEM_BIN_DIR)/$(FW_CEM_NAME).elf

FW_CEM_BIN   := $(FW_CEM_BIN_DIR)/$(FW_CEM_NAME)_iccm.bin \
		$(FW_CEM_BIN_DIR)/$(FW_CEM_NAME)_dccm.bin \
		$(FW_CEM_BIN_DIR)/$(FW_CEM_NAME)_iccm.hex \
		$(FW_CEM_BIN_DIR)/$(FW_CEM_NAME)_dccm.hex

########################
# Targets
########################

$(PKG): $(FW_CEM_BIN)

$(FW_CEM_ELF): FW_ELF_OBJ_DIR := $(FW_CEM_OBJ_DIR)
$(FW_CEM_ELF): FW_ELF_TCF := $(FW_CEM_SHARED_SRC_DIR)/hw/arc.cem.tcf
$(FW_CEM_ELF): FW_ELF_CFLAGS  += -DGIBRALTAR=1 -Hheap=4 -Hstack=0x400 -I$(FW_CEM_SHARED_SRC_DIR) -I$(FW_CEM_SRC_DIR) -I$(SHARED_BASE_ROOT)/include/hw_tables/ -Wno-unused-const-variable
$(FW_CEM_ELF): $(wildcard $(FW_CEM_SRC_DIR)/*.cpp) $(wildcard $(FW_CEM_SRC_DIR)/*.h) $(wildcard $(FW_CEM_SHARED_SRC_DIR)/*.cpp) $(wildcard $(FW_CEM_SHARED_SRC_DIR)/*.h) $(FW_CEM_SHARED_SRC_DIR)/progs/cem_main.cpp


$(FW_CEM_BIN): FW_ELF2HEX_BASE_ADDR := 0x000_0000
$(FW_CEM_BIN): $(FW_CEM_ELF)

$(PKG)-clean:
	@$(RM) -rf $(FW_CEM_OBJ_DIR)
	@$(RM) -rf $(FW_CEM_BIN_DIR)/$(FW_CEM_NAME)*


