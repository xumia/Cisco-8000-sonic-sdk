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

PKG           := firmware-css
PKG-TARGETS   := bin
PKG-PATH      := src/firmware/css

include $(MakefileTemplateRoot)/Makefile.module_vars


########################
# Local stuff
########################

FW_CSS_NAME      := $(PKG-NAME)

FW_CSS_SRC_DIR   := $(MakefileBaseRoot)/$(PKG-PATH)
FW_CSS_BIN_DIR   := $(RES_OUTPUT_DIR)
FW_CSS_OBJ_DIR   := $(MakefileBaseRoot)/$(firmware-css-build-dir)

########################
# File lists
########################

FW_CSS_ELF   := $(FW_CSS_BIN_DIR)/$(FW_CSS_NAME).elf

FW_CSS_BIN   := $(FW_CSS_BIN_DIR)/$(FW_CSS_NAME)_iccm.bin \
                 $(FW_CSS_BIN_DIR)/$(FW_CSS_NAME)_iccm.hex

########################
# Flags
########################
FW_CSS_WARNINGS :=               \
    -Werror                      \
    -Wall                        \
    -Wstrict-prototypes          \
    -Wcast-align                 \
    -Wdeprecated-declarations    \
    -Wdiv-by-zero                \
    -Wendif-labels               \
    -Wfloat-equal                \
    -Wformat-nonliteral          \
    -Wmain                       \
    -Wmissing-declarations       \
    -Wmissing-noreturn           \
    -Wmissing-prototypes         \
    -Wpointer-arith              \
    -Wsequence-point             \
    -Wshadow                     \
    -Wsign-compare


FW_CSS_CFLAGS :=             \
    -Hcrt_initbss            \
    -Hcrt_invcache           \
    -Hcrt_inittimer          \
    -Hcrt_reginit            \
    -fno-const-strings       \
    -Hheap=4096              \
    -Hstack=8192             \
    -Hcrt_initcopy           \
    -Hcrt_fast_memcpy        \
    -Hcrt_fast_memset        \
    -Bcopydata

FW_CSS_INCLUDES := \
    -I$(FW_CSS_SRC_DIR) \
    -I$(SHARED_BASE_ROOT)/include \
    -I$(BASE_OUTPUT_DIR)/include

########################
# Targets
########################

$(PKG): $(FW_CSS_BIN)

$(FW_CSS_ELF): $(nplapi-configured) | api-include
$(FW_CSS_ELF): FW_ELF_OBJ_DIR := $(FW_CSS_OBJ_DIR)
$(FW_CSS_ELF): FW_ELF_TCF := $(FW_CSS_SRC_DIR)/hw/arc.css_pacific.tcf
$(FW_CSS_ELF): FW_ELF_CFLAGS += $(FW_CSS_WARNINGS) $(FW_CSS_CFLAGS) $(FW_CSS_INCLUDES)
$(FW_CSS_ELF): $(wildcard $(FW_CSS_SRC_DIR)/*.cpp) $(wildcard $(FW_CSS_SRC_DIR)/*.h)

$(FW_CSS_BIN): FW_ELF2HEX_BASE_ADDR := 0x0000_0000
$(FW_CSS_BIN): $(FW_CSS_ELF)

$(PKG)-clean:
	@$(RM) -rf $(FW_CSS_OBJ_DIR)
	@$(RM) -rf $(FW_CSS_BIN_DIR)/$(FW_CSS_NAME)*


