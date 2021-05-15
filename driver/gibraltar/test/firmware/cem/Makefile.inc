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

ifndef FW_CEM_NAME
$(error FW_CEM_NAME is not set)
endif

ifndef FW_CEM_SRC_DIR
$(error FW_CEM_SRC_DIR is not set)
endif

ifndef FW_CEM_SHARED_SRC_DIR
$(error FW_CEM_SHARED_SRC_DIR)
endif

ifndef FW_CEM_BIN_DIR
$(error FW_CEM_BIN_DIR is not set)
endif

#######################
# Grabbing settings from central Makefile
#######################

include $(MakefileTemplateRoot)/Makefile.module_pre

PKG 		:= test-firmware-cem
PKG-TARGETS 	:= bin
PKG-PATH 	:= test/firmware/cem

include $(MakefileTemplateRoot)/Makefile.module_vars


########################
# Local staff
########################

FW_CEM_TEST_NAME        := $(PKG-NAME)

FW_CEM_TEST_DIR		:= $(MakefileBaseRoot)/$(PKG-PATH)
FW_CEM_TEST_OBJ_DIR     := $(MakefileBaseRoot)/$(test-firmware-cem-build-dir)

########################
# File lists
########################
FW_CEM_TEST_ELF	             := $(FW_CEM_BIN_DIR)/$(FW_CEM_TEST_NAME)_test.elf

FW_CEM_TEST_SRCS	     := $(wildcard $(FW_CEM_TEST_DIR)/tests/*.cpp)
FW_CEM_TEST_STATUS	     := $(patsubst $(FW_CEM_TEST_DIR)/tests/%_test.cpp, $(FW_CEM_TEST_OBJ_DIR)/test_%.SUCCESS, $(FW_CEM_TEST_SRCS))

FW_CEM_SRC_FILES             := $(wildcard $(FW_CEM_SRC_DIR)/*.cpp) $(wildcard $(FW_CEM_SRC_DIR)/*.h) $(wildcard $(FW_CEM_SHARED_SRC_DIR)/*.cpp) $(wildcard $(FW_CEM_SHARED_SRC_DIR)/*.h)
FW_CEM_TEST_FILES            := $(wildcard $(FW_CEM_TEST_DIR)/*.cpp) $(wildcard $(FW_CEM_TEST_DIR)/*.h) $(wildcard $(FW_CEM_TEST_DIR)/tests/*.cpp)

FW_CEM_BIN_EXT               := iccm.bin dccm.bin iccm.hex dccm.hex

FW_CEM_SIM_UNIT_ELF	     := $(FW_CEM_BIN_DIR)/$(FW_CEM_TEST_NAME)_unit_sim.elf
FW_CEM_SIM_UNIT_BIN          := $(foreach ext, $(FW_CEM_BIN_EXT), $(FW_CEM_BIN_DIR)/$(FW_CEM_TEST_NAME)_unit_sim_$(ext))

FW_CEM_SIM_BASIC_ELF	     := $(FW_CEM_BIN_DIR)/$(FW_CEM_TEST_NAME)_basic_sim.elf
FW_CEM_SIM_BASIC_BIN         := $(foreach ext, $(FW_CEM_BIN_EXT), $(FW_CEM_BIN_DIR)/$(FW_CEM_TEST_NAME)_basic_sim_$(ext))

########################
# Targets
########################

test-firmware-cem-test: 	$(FW_CEM_TEST_STATUS)

test-firmware-cem: 		$(FW_CEM_TEST_ELF)

test-firmware-cem-sim:		test-firmware-cem-sim-unit test-firmware-cem-sim-basic

test-firmware-cem-sim-unit:	$(FW_CEM_SIM_UNIT_BIN)

test-firmware-cem-sim-basic:	$(FW_CEM_SIM_BASIC_BIN)

$(FW_CEM_TEST_ELF): FW_ELF_OBJ_DIR := $(FW_CEM_TEST_OBJ_DIR)
$(FW_CEM_TEST_ELF): FW_ELF_TCF := $(FW_CEM_SHARED_SRC_DIR)/hw/arc.cem.debug.tcf
$(FW_CEM_TEST_ELF): FW_ELF_CFLAGS  += -DGIBRALTAR=1 -I$(FW_CEM_SRC_DIR) -I$(FW_CEM_SHARED_SRC_DIR) -I$(FW_CEM_TEST_DIR) -I$(SHARED_BASE_ROOT)/include/hw_tables/ -DTEST_MODE=1
$(FW_CEM_TEST_ELF): FW_ELF_CFLAGS  += -Wno-unused-variable
$(FW_CEM_TEST_ELF): $(FW_CEM_SRC_FILES) $(FW_CEM_TEST_FILES) $(FW_CEM_SHARED_SRC_DIR)/progs/cem_main.cpp


$(FW_CEM_SIM_UNIT_ELF): FW_ELF_OBJ_DIR := $(FW_CEM_TEST_OBJ_DIR)
$(FW_CEM_SIM_UNIT_ELF): FW_ELF_TCF := $(FW_CEM_SHARED_SRC_DIR)/hw/arc.cem.tcf
$(FW_CEM_SIM_UNIT_ELF): FW_ELF_CFLAGS  += -I$(FW_CEM_SRC_DIR) -I$(FW_CEM_SHARED_SRC_DIR) -I$(SHARED_BASE_ROOT)/include/hw_tables/ -DCEM_SIM=1
$(FW_CEM_SIM_UNIT_ELF): $(FW_CEM_SRC_FILES) $(FW_CEM_TEST_DIR)/progs/sim_unit_main.cpp

$(FW_CEM_SIM_UNIT_BIN): FW_ELF2HEX_BASE_ADDR := 0x000_0000
$(FW_CEM_SIM_UNIT_BIN): $(FW_CEM_SIM_UNIT_ELF)


$(FW_CEM_SIM_BASIC_ELF): FW_ELF_OBJ_DIR := $(FW_CEM_TEST_OBJ_DIR)
$(FW_CEM_SIM_BASIC_ELF): FW_ELF_TCF := $(FW_CEM_SHARED_SRC_DIR)/hw/arc.cem.tcf
$(FW_CEM_SIM_BASIC_ELF): FW_ELF_CFLAGS  += -I$(FW_CEM_SRC_DIR) -I$(FW_CEM_SHARED_SRC_DIR) -I$(SHARED_BASE_ROOT)/include/hw_tables/ -DCEM_SIM=1
$(FW_CEM_SIM_BASIC_ELF): $(FW_CEM_SRC_FILES) $(FW_CEM_TEST_DIR)/progs/sim_basic_main.cpp

$(FW_CEM_SIM_BASIC_BIN): FW_ELF2HEX_BASE_ADDR := 0x000_0000
$(FW_CEM_SIM_BASIC_BIN): $(FW_CEM_SIM_BASIC_ELF)


$(FW_CEM_TEST_STATUS) : $(FW_CEM_TEST_OBJ_DIR)/%.SUCCESS : $(FW_CEM_TEST_ELF)
	@echo ""
	@echo "RUNNING test $*"
	@$(RM) -rf $@
	@echo "DISABLED TEST"
	#env SCL_QUEUE_ON_MAX=1 SNPSLMD_LICENSE_FILE=$(FW_MW_LICENSE) $(FW_MW_DIR)/mdb -av2em $(FW_CEM_TEST_ELF) -tcf $(FW_CEM_SRC_DIR)/hw/arc.cem.debug.tcf -cl -cmd="read $(FW_CEM_TEST_DIR)/test_mdb.cmd $* $(FW_CEM_TEST_OBJ_DIR)"
	#@test -f $@ || { echo "$* FAILED, Exiting ..."; false; }


test-firmware-cem-debug: $(FW_CEM_TEST_ELF)
	env SCL_QUEUE_ON_MAX=1 SNPSLMD_LICENSE_FILE=$(FW_MW_LICENSE) $(FW_MW_DIR)/mdb -av2em -OK -project simple -tcf $(FW_CEM_SRC_DIR)/hw/arc.cem.debug.tcf $(FW_CEM_TEST_ELF)

test-firmware-cem-clean:
	@$(RM) -rf $(FW_CEM_TEST_OBJ_DIR)
	@$(RM) -rf $(FW_CEM_BIN_DIR)/$(FW_CEM_TEST_NAME)*
