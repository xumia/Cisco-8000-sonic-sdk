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


FW_MW_LICENSE           := "51162@ls-csi-01.cisco.com:51162@ls-sjc-01.cisco.com:51162@ls-csi-01-alt.cisco.com:51162@ls-rtp-01.cisco.com"
FW_ELF_CC               := $(FW_MW_DIR)/ccac

# -Hcl          - use small std library
# -Hall_sdata   - use relative reference for variables (small memory)
# -Hmerge       - merge functions
FW_ELF_CFLAGS           := -Hon=Wait_for_license -Hcl -Hcppmw -Hkeepasm -g -Hharvard

ifndef FW_NOOPT
FW_ELF_CFLAGS           += -Os -Hall_sdata -Hmerge
endif

FW_ELF_OBJ_DIR		:= /tmp/you_forgot_to_define_obj_dir
FW_ELF_TCF		:= /tmp/you_forgot_to_set_tcf_file.tcf

%.elf:
	@echo
	@echo BUILD:  $@
	@echo prereq: $^
	@echo source: $(filter %.cpp, $^) $(filter %.c, $^)
	@echo outdir: $(FW_ELF_OBJ_DIR)
	@echo bindir: $(@D)
	@$(MKDIR) -p $(@D)
	@$(MKDIR) -p $(FW_ELF_OBJ_DIR)
	env SCL_QUEUE_ON_MAX=1 SNPSLMD_LICENSE_FILE=$(FW_MW_LICENSE) $(FW_ELF_CC) $(filter %.cpp, $^) $(filter %.c, $^) $(FW_ELF_CFLAGS) -Hkeepasm=$(FW_ELF_OBJ_DIR) -Hobjdir=$(FW_ELF_OBJ_DIR) -tcf=$(FW_ELF_TCF) -o $@ -m >$(FW_ELF_OBJ_DIR)/$(@F).map
	@echo "*** Library size:"
	@$(FW_MW_DIR)/sizeac $@
	@$(FW_MW_DIR)/elfdumpac -t $@ | perl -n -e 'if (/^\W*\d+/) {print;}' | tee $(FW_ELF_OBJ_DIR)/$(@F).elfdump.log | sort -r -n -k 3 | grep FUNC > $(FW_ELF_OBJ_DIR)/$(@F).elfdump.func.log
	@grep _fheap $(FW_ELF_OBJ_DIR)/$(@F).elfdump.log | awk '{print "*** Heap begin: ", $$6, " --> ", $$2}'
	@echo


FW_ELF2HEX_BASE_ADDR  := 0x0000_0000

%_iccm.bin:
	@$(MKDIR) -p $(@D)
	$(FW_MW_DIR)/elf2hex -B -ct -p$(FW_ELF2HEX_BASE_ADDR) $< -o $@

%_iccm.hex:
	@$(MKDIR) -p $(@D)
	$(FW_MW_DIR)/elf2hex -V -ct -p$(FW_ELF2HEX_BASE_ADDR) $< -o $@

%_dccm.bin:
	@$(MKDIR) -p $(@D)
	$(FW_MW_DIR)/elf2hex -B -cldb -p$(FW_ELF2HEX_BASE_ADDR) $< -o $@

%_dccm.hex:
	@$(MKDIR) -p $(@D)
	$(FW_MW_DIR)/elf2hex -V -cld -p$(FW_ELF2HEX_BASE_ADDR) $< -o $@
	-grep -v @ $@ > $@.fixed

%_sys.bin:
	@$(MKDIR) -p $(@D)
	$(FW_MW_DIR)/elf2hex -B -p$(FW_ELF2HEX_BASE_ADDR) $< -o $@

%_sys.hex:
	@$(MKDIR) -p $(@D)
	$(FW_MW_DIR)/elf2hex -V -p$(FW_ELF2HEX_BASE_ADDR) $< -o $@


