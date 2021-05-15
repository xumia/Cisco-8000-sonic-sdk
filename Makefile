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

include build/Makefile.envsetup

MODULES = driver scripts build npl sai tools
# Used to run all sanities except for driver so per-platform sanities can be
# broken out into different make commands
MODULES_STUB = scripts build npl sai tools

VERSION ?= 1.40.1.3

DEBUG ?= 1
OPT ?= 0

PACIFIC_SRC_TARBALL = pacific-sdk-$(VERSION)-src.tar.gz
PACIFIC_BIN_TARBALL = pacific-sdk-$(VERSION).tar.gz

GIBRALTAR_SRC_TARBALL = gibraltar-sdk-$(VERSION)-src.tar.gz
GIBRALTAR_BIN_TARBALL = gibraltar-sdk-$(VERSION).tar.gz

ASIC4_SRC_TARBALL = asic4-sdk-$(VERSION)-src.tar.gz
ASIC4_BIN_TARBALL = asic4-sdk-$(VERSION).tar.gz

ASIC3_SRC_TARBALL = asic3-sdk-$(VERSION)-src.tar.gz
ASIC3_BIN_TARBALL = asic3-sdk-$(VERSION).tar.gz

ASIC5_SRC_TARBALL = asic5-sdk-$(VERSION)-src.tar.gz
ASIC5_BIN_TARBALL = asic5-sdk-$(VERSION).tar.gz


# The code that creates BUILD_TYPE  code is already present in Makefile.top_pre.
# We do not want to create dependency, so we are replicating it here.
ifeq ($(OPT), 0)
    BUILD_TYPE = noopt
else
    BUILD_TYPE = opt$(OPT)
endif

ifeq ($(DEBUG), 1)
    BUILD_TYPE := $(BUILD_TYPE)-debug
endif

ifeq ($(USE_CLANG), 1)
    BUILD_TYPE := $(BUILD_TYPE)-clang
endif

export sai-ver ?= 1.7.1

# Reconsider if AAPL version should be defined here. This currently used in external source release.
aapl-ver := aapl-2.7.3

ext-src-build-dir := driver/gibraltar/out/$(BUILD_TYPE)/build/src

srm-ver := 0.33.0.1670
srm-include-path := $(ext-src-build-dir)/srm/$(srm-ver)/srm_public_release_$(srm-ver)/api

esilicon-ver := 20190517
esilicon-include-path := $(ext-src-build-dir)/esilicon/$(esilicon-ver)/ts_7ff_hbm2llhbmphy_ins_ccode_v1p2_$(esilicon-ver)/c-code/c-code-setup

ext-src-build-dir-pl := driver/asic4/out/$(BUILD_TYPE)/build/src

srm-ver-pl := 0.21.0.1178
srm-include-path-pl := $(ext-src-build-dir-pl)/srm/$(srm-ver-pl)/srm_public_release_$(srm-ver-pl)/api

esilicon-ver-pl := 20190517
esilicon-include-path-pl := $(ext-src-build-dir-pl)/esilicon/$(esilicon-ver-pl)/ts_7ff_hbm2llhbmphy_ins_ccode_v1p2_$(esilicon-ver-pl)/c-code/c-code-setup

.PHONY: $(MODULES)
all: $(MODULES)
$(MODULES): %:
	$(MAKE) -C $* all

TEST_MODULES = $(foreach module, $(MODULES), $(module)-test)
.PHONY: test $(TEST_MODULES)
test: $(TEST_MODULES)
$(TEST_MODULES): %-test: %
	$(MAKE) -C $* test

VERIFY_FORMAT_MODULES = $(foreach module, $(MODULES), $(module)-verify-format)
.PHONY: $(VERIFY_FORMAT_MODULES)
verify-format: $(VERIFY_FORMAT_MODULES)
$(VERIFY_FORMAT_MODULES): %-verify-format:
	$(MAKE) -C $* verify-format

APPLY_FORMAT_MODULES = $(foreach module, $(MODULES), $(module)-apply-format)
.PHONY: $(APPLY_FORMAT_MODULES)
apply-format: $(APPLY_FORMAT_MODULES)
$(APPLY_FORMAT_MODULES): %-apply-format:
	$(MAKE) -C $* apply-format

SANITY_MODULES = $(foreach module, $(MODULES), $(module)-sanity)
.PHONY: sanity $(SANITY_MODULES)
sanity: $(SANITY_MODULES)
$(SANITY_MODULES): %-sanity: %
	$(MAKE) -C $* sanity

SANITY_MODULES_STUB = $(foreach module_stub, $(MODULES_STUB), $(module_stub)-sanity)
.PHONY: sanity_gen $(SANITY_MODULES_STUB)
sanity_gen: $(SANITY_MODULES_STUB)
$(SANITY_MODULES_STUB): %-sanity: %
	$(MAKE) -C $* sanity

EXT_SRC_MODULES = $(foreach module, $(MODULES), $(module)-ext-src)
.PHONY: ext-src $(EXT_SRC_MODULES)
ext-src: $(EXT_SRC_MODULES)
$(EXT_SRC_MODULES): %-ext-src:
	$(MAKE) -C $* ext-src

CUSTOMER_SRC_MODULES = $(foreach module, $(MODULES), $(module)-customer-src)
.PHONY: customer-src $(CUSTOMER_SRC_MODULES)
customer-src: $(CUSTOMER_SRC_MODULES)
$(CUSTOMER_SRC_MODULES): %-customer-src:
	$(MAKE) -C $* customer-src

CUSTOMER_SRC_MODULES = $(foreach module, $(MODULES), $(module)-pacific-customer-src)
.PHONY: pacific-customer-src $(CUSTOMER_SRC_MODULES)
pacific-customer-src: $(CUSTOMER_SRC_MODULES)
$(CUSTOMER_SRC_MODULES): %-pacific-customer-src:
	$(MAKE) -C $* pacific-customer-src

CLEAN_MODULES = $(foreach module, $(MODULES), $(module)-clean)
.PHONY: clean $(CLEAN_MODULES)
clean: $(CLEAN_MODULES)
$(CLEAN_MODULES): %-clean:
	$(MAKE) -C $* clean

# Inter-module dependencies
sai: driver

$(PACIFIC_SRC_TARBALL) $(GIBRALTAR_SRC_TARBALL) $(ASIC4_SRC_TARBALL) $(ASIC3_SRC_TARBALL) $(ASIC5_SRC_TARBALL): %-sdk-$(VERSION)-src.tar.gz:
	# Change the Makefile targets to be asic specific
	sed -e 's/PROJECTS = pacific gibraltar asic4 asic3 asic5/PROJECTS = $*/g' driver/Makefile > driver/Makefile.$*
	tar cfh $*-sdk-$(VERSION)-src.tar \
		--transform "s,^driver/Makefile.$*,driver/Makefile,S" \
		--transform "s,^,$*-sdk-$(VERSION)-src/,S" \
		--show-transformed-names \
		--exclude-backups \
		--exclude-vcs \
		--exclude='__pycache__' \
		--exclude='driver/$*/out' \
		--exclude='driver/$*/examples/out' \
		--exclude='npl/$*/tests' \
		--exclude='driver/$*/externals/lab_env/npu/tests/av_tests_files/snake_for_tester' \
		--exclude='driver/$*/externals/lab_env/global/reg_dumps' \
		-- Makefile build tools driver/shared driver/$* driver/Makefile.$* \
		   externals/jansson npl sai scripts CHANGES ERRATAS \
		   README.BIN README.SRC \
		   devices/pacific \
		   devices/gibraltar \
		   devices/akpg/common \
		   devices/akpg/asic4 \
		   devices/akpg/asic3 \
		   devices/akpg/asic5 \
		   submodules/3rd-party/packages/avago \
		   submodules/3rd-party/packages/googletest \
		   submodules/3rd-party/packages/jansson/2.12 \
		   submodules/3rd-party/packages/sai/$(sai-ver) \
		   submodules/3rd-party/packages/cereal

	gzip -9 $*-sdk-$(VERSION)-src.tar
	rm driver/Makefile.$*

pacific-release-ext-src: driver-ext-src
	rm -rf out
	rm -rf pacific-sdk-$(VERSION)-src
	rm -f pacific-sdk-$(VERSION)-ext-src.tar.gz
	mkdir -p out/build
	sed -e "s/PREBUILT_DEPENDS.*/PREBUILT_DEPENDS := 1/" build/Makefile.top_pre > out/build/Makefile.top_pre
	mkdir -p out/driver/pacific/shared/include
	mkdir -p out/driver/pacific/externals
	mkdir -p out/driver/pacific/prebuilt
	cp -R driver/pacific/out/$(BUILD_TYPE)/{lib,lib_static,pylib,res} out/driver/pacific/prebuilt
	mkdir -p out/driver/pacific/externals/avago
	cp -R driver/pacific/out/$(BUILD_TYPE)/res/*.rom out/driver/pacific/externals/avago/.
	cp -R driver/pacific/out/$(BUILD_TYPE)/build/src/aapl/$(aapl-ver)/src/include out/driver/pacific/shared/include/aapl
	mkdir -p out/driver/pacific/out/$(BUILD_TYPE)/build/src/aapl/$(aapl-ver)/src
	cp -R driver/pacific/out/$(BUILD_TYPE)/build/src/aapl/$(aapl-ver)/src/include out/driver/pacific/out/$(BUILD_TYPE)/build/src/aapl/$(aapl-ver)/src/.
	sed -e "s/ gibraltar//" driver/Makefile > out/driver/Makefile
	tar cfh pacific-sdk-$(VERSION)-ext-src.tar \
		--transform "s,^,pacific-sdk-$(VERSION)-src/,S" --show-transformed-names \
		--exclude-backups \
		--exclude-vcs \
		--exclude='__pycache__' \
		--exclude='driver/pacific/out' \
		--exclude='driver/pacific/examples/out' \
		--exclude='driver/pacific/src/aapl/*.patch' \
		--exclude='driver/shared/test/hw_tables/lpm/inputs' \
		--exclude='driver/shared/test/hw_tables/lpm/test_scaled_down_logical_lpm.cpp' \
		--exclude='driver/shared/test/hw_tables/lpm/test_logical_lpm_actions.cpp' \
		--exclude='npl/pacific/tests' \
		--exclude='npl/gibraltar' \
		--exclude='npl/out' \
		--exclude='sai/out' \
		--exclude='tools/out' \
		--exclude='driver/pacific/externals/avago' \
		--exclude='driver/pacific/externals/lab_env/npu/tests/av_tests_files/snake_for_tester' \
		--exclude='driver/pacific/externals/lab_env/global/reg_dumps' \
		-- Makefile build driver/shared driver/pacific externals/jansson npl sai scripts devices CHANGES README.BIN README.SRC \
		   submodules/3rd-party/packages/sai/$(sai-ver) submodules/3rd-party/packages/cereal tools
	mv out pacific-sdk-$(VERSION)-src
	tar vf pacific-sdk-$(VERSION)-ext-src.tar \
		--append pacific-sdk-$(VERSION)-src
	gzip pacific-sdk-$(VERSION)-ext-src.tar

asic4-release-ext-src: driver-ext-src
	rm -rf out
	rm -rf asic4-sdk-$(VERSION)-src
	rm -f asic4-sdk-$(VERSION)-ext-src.tar.gz
	mkdir -p out/build
	sed -e "s/PREBUILT_DEPENDS.*/PREBUILT_DEPENDS := 1/" build/Makefile.top_pre > out/build/Makefile.top_pre
	mkdir -p out/driver/asic4/shared/include
	mkdir -p out/driver/asic4/externals
	mkdir -p out/driver/asic4/prebuilt/include/srm/platform
	cp -R driver/asic4/out/$(BUILD_TYPE)/{lib,lib_static,pylib,res} out/driver/asic4/prebuilt
	-rm out/driver/asic4/pylib/*srmcli*
	mkdir -p out/driver/asic4/externals/avago
	cp -R driver/asic4/out/$(BUILD_TYPE)/res/*.rom out/driver/asic4/externals/avago/.
	cp -R driver/asic4/out/$(BUILD_TYPE)/build/src/aapl/$(aapl-ver)/src/include out/driver/asic4/shared/include/aapl
	mkdir -p out/driver/asic4/out/$(BUILD_TYPE)/build/src/aapl/$(aapl-ver)/src
	cp -R driver/asic4/out/$(BUILD_TYPE)/build/src/aapl/$(aapl-ver)/src/include out/driver/asic4/out/$(BUILD_TYPE)/build/src/aapl/$(aapl-ver)/src/.
	cp $(srm-include-path-pl)/*.h out/driver/asic4/prebuilt/include/srm
	cp $(srm-include-path-pl)/platform/*.h out/driver/asic4/prebuilt/include/srm/platform
	sed -e "s/ pacific//" driver/Makefile > out/driver/Makefile
	sed -e "s/..\/..\/tools/tools/" driver/asic4/Makefile > out/driver/asic4/Makefile
	mkdir -p out/driver/asic4/src/srm
	cp driver/asic4/src/srm/Makefile.inc out/driver/asic4/src/srm/
	cp driver/asic4/src/srm/swig.i out/driver/asic4/src/srm/
	mkdir -p out/driver/asic4/shared/include/esilicon
	cp $(esilicon-include-path-pl)/*.h out/driver/asic4/shared/include/esilicon/
	tar cfh asic4-sdk-$(VERSION)-ext-src.tar \
		--transform "s,^,asic4-sdk-$(VERSION)-src/,S" --show-transformed-names \
		--exclude-backups \
		--exclude-vcs \
		--exclude='__pycache__' \
		--exclude='projects' \
		--exclude='driver/asic4/out' \
		--exclude='driver/asic4/examples/out' \
		--exclude='driver/asic4/src/aapl/*.patch' \
		--exclude='driver/asic4/src/srm' \
		--exclude='driver/shared/test/hw_tables/lpm/inputs' \
		--exclude='driver/shared/test/hw_tables/lpm/test_scaled_down_logical_lpm.cpp' \
		--exclude='driver/shared/test/hw_tables/lpm/test_logical_lpm_actions.cpp' \
		--exclude='driver/shared/test/hw_tables/lpm/customer_tables_tests' \
		--exclude='driver/asic4/shared/test/hw_tables/lpm/inputs/customer_tables' \
		--exclude='npl/pacific/tests' \
		--exclude='npl/asic4' \
		--exclude='npl/out' \
		--exclude='sai/out' \
		--exclude='tools/out' \
		--exclude='driver/asic4/externals/avago' \
		--exclude='driver/asic4/externals/srm' \
		--exclude='driver/asic4/externals/esilicon' \
		--exclude='driver/asic4/externals/lab_env/npu/tests/av_tests_files/snake_for_tester' \
		--exclude='driver/asic4/externals/lab_env/global/reg_dumps' \
		--exclude='driver/asic4/nbproject' \
		--exclude='sdk_cmd_file.rest_of_init.txt' \
		-- Makefile build driver/shared driver/asic4 externals/jansson npl sai scripts devices CHANGES README.BIN README.SRC \
		   submodules/3rd-party/packages/sai/$(sai-ver) submodules/3rd-party/packages/cereal tools
	mv out asic4-sdk-$(VERSION)-src
	tar vf asic4-sdk-$(VERSION)-ext-src.tar \
		--exclude='__pycache__' \
		--append asic4-sdk-$(VERSION)-src
	gzip asic4-sdk-$(VERSION)-ext-src.tar

asic3-release-ext-src: driver-ext-src
	rm -rf out
	rm -rf asic3-sdk-$(VERSION)-src
	rm -f asic3-sdk-$(VERSION)-ext-src.tar.gz
	mkdir -p out/build
	sed -e "s/PREBUILT_DEPENDS.*/PREBUILT_DEPENDS := 1/" build/Makefile.top_pre > out/build/Makefile.top_pre
	mkdir -p out/driver/asic3/shared/include
	mkdir -p out/driver/asic3/externals
	mkdir -p out/driver/asic3/prebuilt/include/srm/platform
	cp -R driver/asic3/out/$(BUILD_TYPE)/{lib,lib_static,pylib,res} out/driver/asic3/prebuilt
	-rm out/driver/asic3/pylib/*srmcli*
	mkdir -p out/driver/asic3/externals/avago
	cp -R driver/asic3/out/$(BUILD_TYPE)/res/*.rom out/driver/asic3/externals/avago/.
	cp -R driver/asic3/out/$(BUILD_TYPE)/build/src/aapl/$(aapl-ver)/src/include out/driver/asic3/shared/include/aapl
	mkdir -p out/driver/asic3/out/$(BUILD_TYPE)/build/src/aapl/$(aapl-ver)/src
	cp -R driver/asic3/out/$(BUILD_TYPE)/build/src/aapl/$(aapl-ver)/src/include out/driver/asic3/out/$(BUILD_TYPE)/build/src/aapl/$(aapl-ver)/src/.
	cp $(srm-include-path-pl)/*.h out/driver/asic3/prebuilt/include/srm
	cp $(srm-include-path-pl)/platform/*.h out/driver/asic3/prebuilt/include/srm/platform
	sed -e "s/ pacific//" driver/Makefile > out/driver/Makefile
	sed -e "s/..\/..\/tools/tools/" driver/asic3/Makefile > out/driver/asic3/Makefile
	mkdir -p out/driver/asic3/src/srm
	cp driver/asic3/src/srm/Makefile.inc out/driver/asic3/src/srm/
	cp driver/asic3/src/srm/swig.i out/driver/asic3/src/srm/
	mkdir -p out/driver/asic3/shared/include/esilicon
	cp $(esilicon-include-path-pl)/*.h out/driver/asic3/shared/include/esilicon/
	tar cfh asic3-sdk-$(VERSION)-ext-src.tar \
		--transform "s,^,asic3-sdk-$(VERSION)-src/,S" --show-transformed-names \
		--exclude-backups \
		--exclude-vcs \
		--exclude='__pycache__' \
		--exclude='projects' \
		--exclude='driver/asic3/out' \
		--exclude='driver/asic3/examples/out' \
		--exclude='driver/asic3/src/aapl/*.patch' \
		--exclude='driver/asic3/src/srm' \
		--exclude='driver/shared/test/hw_tables/lpm/inputs' \
		--exclude='driver/shared/test/hw_tables/lpm/test_scaled_down_logical_lpm.cpp' \
		--exclude='driver/shared/test/hw_tables/lpm/test_logical_lpm_actions.cpp' \
		--exclude='driver/shared/test/hw_tables/lpm/customer_tables_tests' \
		--exclude='driver/asic3/shared/test/hw_tables/lpm/inputs/customer_tables' \
		--exclude='npl/pacific/tests' \
		--exclude='npl/asic3' \
		--exclude='npl/out' \
		--exclude='sai/out' \
		--exclude='tools/out' \
		--exclude='driver/asic3/externals/avago' \
		--exclude='driver/asic3/externals/srm' \
		--exclude='driver/asic3/externals/esilicon' \
		--exclude='driver/asic3/externals/lab_env/npu/tests/av_tests_files/snake_for_tester' \
		--exclude='driver/asic3/externals/lab_env/global/reg_dumps' \
		--exclude='driver/asic3/nbproject' \
		--exclude='sdk_cmd_file.rest_of_init.txt' \
		-- Makefile build driver/shared driver/asic3 externals/jansson npl sai scripts devices CHANGES README.BIN README.SRC \
		   submodules/3rd-party/packages/sai/$(sai-ver) submodules/3rd-party/packages/cereal tools
	mv out asic3-sdk-$(VERSION)-src
	tar vf asic3-sdk-$(VERSION)-ext-src.tar \
		--exclude='__pycache__' \
		--append asic3-sdk-$(VERSION)-src
	gzip asic3-sdk-$(VERSION)-ext-src.tar

asic5-release-ext-src: driver-ext-src
	rm -rf out
	rm -rf asic5-sdk-$(VERSION)-src
	rm -f asic5-sdk-$(VERSION)-ext-src.tar.gz
	mkdir -p out/build
	sed -e "s/PREBUILT_DEPENDS.*/PREBUILT_DEPENDS := 1/" build/Makefile.top_pre > out/build/Makefile.top_pre
	mkdir -p out/driver/asic5/shared/include
	mkdir -p out/driver/asic5/externals
	mkdir -p out/driver/asic5/prebuilt/include/srm/platform
	cp -R driver/asic5/out/$(BUILD_TYPE)/{lib,lib_static,pylib,res} out/driver/asic5/prebuilt
	-rm out/driver/asic5/pylib/*srmcli*
	sed -e "s/ pacific//" driver/Makefile > out/driver/Makefile
	sed -e "s/..\/..\/tools/tools/" driver/asic5/Makefile > out/driver/asic5/Makefile
	tar cfh asic5-sdk-$(VERSION)-ext-src.tar \
		--transform "s,^,asic5-sdk-$(VERSION)-src/,S" --show-transformed-names \
		--exclude-backups \
		--exclude-vcs \
		--exclude='__pycache__' \
		--exclude='projects' \
		--exclude='driver/asic5/out' \
		--exclude='driver/asic5/examples/out' \
		--exclude='driver/shared/test/hw_tables/lpm/inputs' \
		--exclude='driver/shared/test/hw_tables/lpm/test_scaled_down_logical_lpm.cpp' \
		--exclude='driver/shared/test/hw_tables/lpm/test_logical_lpm_actions.cpp' \
		--exclude='driver/shared/test/hw_tables/lpm/customer_tables_tests' \
		--exclude='driver/asic5/shared/test/hw_tables/lpm/inputs/customer_tables' \
		--exclude='npl/pacific/tests' \
		--exclude='npl/asic5' \
		--exclude='npl/out' \
		--exclude='sai/out' \
		--exclude='tools/out' \
		--exclude='driver/asic5/externals/lab_env/npu/tests/av_tests_files/snake_for_tester' \
		--exclude='driver/asic5/externals/lab_env/global/reg_dumps' \
		--exclude='driver/asic5/nbproject' \
		--exclude='sdk_cmd_file.rest_of_init.txt' \
		-- Makefile build driver/shared driver/asic5 externals/jansson npl sai scripts devices CHANGES README.BIN README.SRC \
		   submodules/3rd-party/packages/sai/$(sai-ver) submodules/3rd-party/packages/cereal tools
	mv out asic5-sdk-$(VERSION)-src
	tar vf asic5-sdk-$(VERSION)-ext-src.tar \
		--exclude='__pycache__' \
		--append asic5-sdk-$(VERSION)-src
	gzip asic5-sdk-$(VERSION)-ext-src.tar

prebuilt-dir := out/driver/gibraltar/prebuilt
pacific-prebuilt-dir := out/driver/pacific/prebuilt

gibraltar-modify-files := lld/Makefile.inc \
                          lld/swig.i \
                          lld/ll_device_context.cpp \
                          lld/ll_device_context.h \
                          lld/parse_context.cpp \
                          lld/parse_context.h \
                          nsim_provider/nsim_translator_command.h \
                          apb/apb_impl.cpp \
                          hw_tables/cem.cpp \
                          hw_tables/lpm/logical_lpm_impl.cpp \
                          hw_tables/lpm/lpm_core.cpp \
                          kernel/leaba_nic.c \
                          kernel/leaba_nic_v2_specific.c \
                          kernel/leaba_registers.h \
                          cpu2jtag/cpu2jtag_drive_states.h \
                          cpu2jtag/cpu2jtag_drive_states.cpp \
                          hld/npu/la_acl_key_profile_base.cpp \
                          ../include/nsim_provider/nsim_provider.h \
                          ../test/api/packet_test_utils.py \
                          ../test/api/uut_provider.py \
                          ../test/nsim_provider/nsim_provider.cpp \
                          ../test/nsim_provider/nsim_provider_c_api.cpp \
                          ../test/nsim_provider/nsim_provider_rpc_api.cpp \
                          ../test/nsim_provider/nsim_test_flow.cpp \
                          ../test/nsim_provider/swig.i

gibraltar-modify-files-src = $(foreach filename, $(gibraltar-modify-files), driver/gibraltar/shared/src/$(filename)) 
gibraltar-modify-files-out = $(foreach filename, $(gibraltar-modify-files), out/driver/gibraltar/shared/src/$(filename)) 

out/driver/gibraltar/shared/.ready: 
	rm -rf out
	mkdir -p out/driver/gibraltar
	cp -RL driver/gibraltar/shared out/driver/gibraltar
	touch $@

$(gibraltar-modify-files-out): out/driver/gibraltar/shared/.ready
$(gibraltar-modify-files-out): $(gibraltar-modify-files-patch)
$(gibraltar-modify-files-out): out/%: %
	mkdir -p $(@D)
	# patch command touches output file even if it fails
	patch --follow-symlinks -p0 $< $<.gibraltar.patch -o $@.copy
	cp $@.copy $@
	rm $@.copy

# NOTE: GB patches are also handling shared files patching !!!
pacific-modify-files := $(gibraltar-modify-files)
pacific-modify-files-src = $(foreach filename, $(pacific-modify-files), driver/pacific/shared/src/$(filename)) 
pacific-modify-files-out = $(foreach filename, $(pacific-modify-files), out/driver/pacific/shared/src/$(filename)) 

out/driver/pacific/shared/.ready: 
	rm -rf out
	mkdir -p out/driver/pacific
	cp -RL driver/pacific/shared out/driver/pacific
	touch $@

	
# patch command touches output file even if it fails 
# NOTE: GB patches are also handling shared files patching !!!
$(pacific-modify-files-out): out/driver/pacific/shared/.ready
$(pacific-modify-files-out): out/%: %
	mkdir -p $(@D)
	patch --follow-symlinks -p0 $< $<.gibraltar.patch -o $@.copy
	cp $@.copy $@
	rm $@.copy



SED_ASIC_CMD :=-e "s/asic3/asic3/g" -e "s/asic4/asic4/g" -e "s/asic5/asic5/g" -e "s/asic6/asic6/g" -e "s/asic7/asic7/g"
SED_ASIC_CMD +=-e "s/ASIC3/ASIC3/g" -e "s/ASIC4/ASIC4/g" -e "s/ASIC5/ASIC5/g" -e "s/ASIC6/ASIC6/g" -e "s/ASIC7/ASIC7/g"
SED_ASIC_CMD +=-e "s/Asic3/Asic3/g" -e "s/Asic4/Asic4/g" -e "s/Asic5/Asic5/g" -e "s/Asic6/Asic6/g" -e "s/Asic7/Asic7/g"

pacific-release-customer-src: driver-pacific-customer-src $(pacific-modify-files-out)
	rm -rf pacific-sdk-$(VERSION)-src
	rm -f pacific-sdk-$(VERSION)-customer-src.tar.gz
	mkdir -p out/build
	sed -e "s/export PREBUILT_DEPENDS ?= 0/export PREBUILT_DEPENDS ?= 1/;    \
			s/export NO_NPL ?= 0/export NO_NPL ?= 1/;					     \
			s/export GENERATE_DOCS ?= 1/export GENERATE_DOCS ?= 0/; 	     \
			s/export SIMULATOR ?= 0/export SIMULATOR ?= 1/;					 \
			s/export NO_NSIM ?= 0/export NO_NSIM ?= $(NO_NSIM)/;" 			 \
			build/Makefile.top_pre > out/build/Makefile.top_pre
	sed -e "s/BUILD_FIRMWARE ?= 1/BUILD_FIRMWARE ?= 0/" driver/pacific/Makefile > out/driver/pacific/Makefile
	mkdir -p out/driver/pacific/externals
	mkdir -p out/scripts
	mkdir -p out/driver/pacific/test
	mkdir -p out/driver/pacific/examples
	mkdir -p out/driver/pacific/externals/avago
	mkdir -p out/devices/pacific/leaba_defined/hw_definitions/
	mkdir -p out/driver/pacific/src/hld/system/

	mkdir -p $(pacific-prebuilt-dir)/build/shared/src/nsim_provider
	mkdir -p $(pacific-prebuilt-dir)/build/shared/src/nplapi/compiled/api/json
	mkdir -p $(pacific-prebuilt-dir)/build/src/ra
	mkdir -p $(pacific-prebuilt-dir)/build/src/hld
	mkdir -p $(pacific-prebuilt-dir)/lib
	mkdir -p $(pacific-prebuilt-dir)/lib_static
	mkdir -p $(pacific-prebuilt-dir)/pylib

	cp -R driver/pacific/out/$(BUILD_TYPE)/res $(pacific-prebuilt-dir)
	cp -R driver/pacific/out/$(BUILD_TYPE)/lib/*npl* $(pacific-prebuilt-dir)/lib/.
	cp -R driver/pacific/out/$(BUILD_TYPE)/build/shared/src/nplapi/*.* $(pacific-prebuilt-dir)/build/shared/src/nplapi
	cp -R driver/pacific/out/$(BUILD_TYPE)/build/shared/src/nplapi/.npl* $(pacific-prebuilt-dir)/build/shared/src/nplapi
	cp -R driver/pacific/out/$(BUILD_TYPE)/build/shared/src/nplapi/compiled/json $(pacific-prebuilt-dir)/build/shared/src/nplapi/compiled
	cp -R driver/pacific/out/$(BUILD_TYPE)/build/shared/src/nplapi/compiled/python_api $(pacific-prebuilt-dir)/build/shared/src/nplapi/compiled
	cp -R driver/pacific/out/$(BUILD_TYPE)/build/shared/src/nplapi/compiled/api $(pacific-prebuilt-dir)/build/shared/src/nplapi/compiled
	cp -R driver/pacific/out/$(BUILD_TYPE)/build/shared/src/nplapi/compiled/api/json/npl_tables_locations.json $(pacific-prebuilt-dir)/build/shared/src/nplapi/compiled/api/json
	cp -R driver/pacific/externals/avago/* out/driver/pacific/externals/avago/.
	cp -R driver/pacific/out/$(BUILD_TYPE)/build/src/hld/*.cpp $(pacific-prebuilt-dir)/build/src/hld
	cp -R driver/pacific/out/$(BUILD_TYPE)/build/src/hld/*.h $(pacific-prebuilt-dir)/build/src/hld
	cp -R driver/pacific/out/$(BUILD_TYPE)/build/src/ra/ra_translator_creator_base.h $(pacific-prebuilt-dir)/build/src/ra
	
	cp -R driver/pacific/out/$(BUILD_TYPE)/build/shared/src/nsim_provider/nsim_translator_creator_base.h $(pacific-prebuilt-dir)/build/shared/src/nsim_provider

ifeq ($(SIMULATOR), 1)
	cp -R driver/pacific/out/$(BUILD_TYPE)/build/shared/src/nplapi/compiled/$(NPSUITE_ARCHIVE_FILENAME) $(pacific-prebuilt-dir)/build/shared/src/nplapi/compiled/$(NPSUITE_ARCHIVE_FILENAME)
	mkdir -p $(pacific-prebuilt-dir)/npsuite
	$(PYTHON_BIN) $(NPSUITE_ROOT)/scripts/nsim_only_release.py --nsim-files $(NPSUITE_ROOT)/simulator_only_files.txt --destination $(pacific-prebuilt-dir)/npsuite
endif
	sed $(SED_ASIC_CMD) driver/Makefile > out/driver/Makefile
	sed $(SED_ASIC_CMD) -e "s/ASIC-LIST := pacific gibraltar asic4 asic3 asic5 asic7/ASIC-LIST := pacific gibraltar/g" Makefile > out/Makefile
	sed $(SED_ASIC_CMD) scripts/sim_run.sh > out/scripts/sim_run.sh
	cp -RL driver/pacific/test/hld out/driver/pacific/test/.
	cp driver/pacific/shared/include/lld/gibraltar/* out/driver/pacific/shared/include/lld/
	cp -R driver/pacific/examples/* out/driver/pacific/examples/
	cp devices/pacific/leaba_defined/hw_definitions/npsuite_lbr.json out/devices/pacific/leaba_defined/hw_definitions/
	cp driver/pacific/src/hld/system/mac_pool_port.cpp out/driver/pacific/src/hld/system/
	cp driver/pacific/src/hld/state_writer.cpp out/driver/pacific/src/hld/

	grep -IZril -e asic3 -e asic4 -e asic5 -e asic6 -e asic7 \
$(pacific-prebuilt-dir) \
out/driver/pacific/shared \
out/driver/pacific/src/hld \
out/driver/pacific/examples \
out/driver/pacific/test \
| xargs -0 -l sed -i $(SED_ASIC_CMD)
	sed -i $(SED_ASIC_CMD) out/devices/pacific/leaba_defined/hw_definitions/npsuite_lbr.json
	sed -i -e 's@#include "lld/asic3_tree.h"@@g' -e 's@#include "lld/asic4_tree.h"@@g' -e 's@#include "lld/asic5_tree.h"@@g' out/driver/pacific/shared/src/apb/serialize_config.cfg
	echo -e '\nskip-class silicon_one::d2d_iface_impl\nskip-class silicon_one::d2d_iface\n' >> out/driver/pacific/shared/src/lld/serialize_config.cfg
	tar cfh pacific-sdk-$(VERSION)-customer-src.tar \
		--transform "s,^,pacific-sdk-$(VERSION)-src/,S" --show-transformed-names \
		--exclude-backups \
		--exclude-vcs \
		--exclude='__pycache__' \
		--exclude='projects' \
		--exclude='driver/pacific/out' \
		--exclude='driver/pacific/examples/out' \
		--exclude='driver/pacific/src/srm' \
		--exclude='driver/pacific/shared' \
		--exclude='npl' \
		--exclude='build/out' \
		--exclude='sai/out' \
		--exclude='scripts/out' \
		--exclude='scripts/refactor' \
		--exclude='tools/out' \
		--exclude='driver/pacific/externals/avago' \
		--exclude='driver/pacific/externals/lab_env/npu/tests/av_tests_files/snake_for_tester' \
		--exclude='driver/pacific/externals/lab_env/global/reg_dumps' \
		--exclude='driver/pacific/manufacturing' \
		--exclude='driver/pacific/nbproject' \
		--exclude='driver/pacific/test/hld' \
		--exclude='sdk_cmd_file.rest_of_init.txt' \
		--exclude='*.npl' \
		--exclude='*.swp' \
		--exclude='*asic3*'\
		--exclude='*asic4*'\
		--exclude='*asic5*'\
		--exclude='*.gibraltar.patch'\
		--exclude='d2d_iface_impl.cpp'\
		--exclude='devices/gibraltar/lbr.pd_ver_2.0/unused_lbrs'\
		-- build license driver/pacific externals/jansson npl sai scripts devices/pacific devices/gibraltar \
		   submodules/3rd-party/packages/sai/$(sai-ver) submodules/3rd-party/packages/cereal tools
	mv out pacific-sdk-$(VERSION)-src
	tar vf pacific-sdk-$(VERSION)-customer-src.tar \
		--exclude='__pycache__' \
		--exclude='*asic3*'\
		--exclude='*asic4*'\
		--exclude='*asic5*'\
		--exclude='*.gibraltar.patch'\
		--exclude='d2d_iface_impl.cpp'\
		--exclude='pacific-sdk-$(VERSION)-src/driver/pacific/shared/manufacturing' \
		--exclude='pacific-sdk-$(VERSION)-src/driver/pacific/shared/shared/src/lld' \
		--exclude='pacific-sdk-$(VERSION)-src/driver/pacific/shared/test/hw_tables/lpm/inputs' \
		--exclude='pacific-sdk-$(VERSION)-src/driver/pacific/shared/test/hw_tables/lpm/test_scaled_down_logical_lpm.cpp' \
		--exclude='pacific-sdk-$(VERSION)-src/driver/pacific/shared/test/hw_tables/lpm/test_logical_lpm_actions.cpp' \
		--exclude='pacific-sdk-$(VERSION)-src/driver/pacific/shared/test/hw_tables/lpm/customer_tables_tests' \
		--exclude='pacific-sdk-$(VERSION)-src/driver/pacific/shared/test/hw_tables/lpm/inputs/customer_tables' \
		--exclude='pacific-sdk-$(VERSION)-src/driver/pacific/shared/test/lld/test_device_simulator.cpp' \
		--exclude='pacific-sdk-$(VERSION)-src/driver/pacific/shared/src/hw_tables/*/*_asic4.*' \
		--append pacific-sdk-$(VERSION)-src
	gzip pacific-sdk-$(VERSION)-customer-src.tar


gibraltar-release-customer-src: driver-customer-src $(gibraltar-modify-files-out)
	rm -rf gibraltar-sdk-$(VERSION)-src
	rm -f gibraltar-sdk-$(VERSION)-customer-src.tar.gz
	mkdir -p out/build
	sed -e "s/export PREBUILT_DEPENDS ?= 0/export PREBUILT_DEPENDS ?= 1/;    \
			s/export NO_NPL ?= 0/export NO_NPL ?= 1/;					     \
			s/export GENERATE_DOCS ?= 1/export GENERATE_DOCS ?= 0/; 	     \
			s/export SIMULATOR ?= 0/export SIMULATOR ?= 1/;					 \
			s/export NO_NSIM ?= 0/export NO_NSIM ?= $(NO_NSIM)/;" 			 \
			build/Makefile.top_pre > out/build/Makefile.top_pre
	sed -e "s/BUILD_FIRMWARE ?= 1/BUILD_FIRMWARE ?= 0/" driver/gibraltar/Makefile > out/driver/gibraltar/Makefile
	mkdir -p out/driver/gibraltar/externals
	mkdir -p out/scripts
	mkdir -p out/driver/gibraltar/test
	mkdir -p $(prebuilt-dir)/include/srm/platform
	mkdir -p $(prebuilt-dir)/build/shared/src/nsim_provider
	mkdir -p $(prebuilt-dir)/build/shared/src/nplapi/compiled/api/json
	mkdir -p $(prebuilt-dir)/build/src/ra
	mkdir -p $(prebuilt-dir)/lib
	mkdir -p $(prebuilt-dir)/lib_static
	mkdir -p $(prebuilt-dir)/pylib
	cp -R driver/gibraltar/out/$(BUILD_TYPE)/res $(prebuilt-dir)
	cp -R driver/gibraltar/out/$(BUILD_TYPE)/lib/*npl* $(prebuilt-dir)/lib/.
	cp -R driver/gibraltar/out/$(BUILD_TYPE)/lib/*srm* $(prebuilt-dir)/lib/.
	cp -R driver/gibraltar/out/$(BUILD_TYPE)/lib_static/*srm* $(prebuilt-dir)/lib_static/.
	cp -R driver/gibraltar/out/$(BUILD_TYPE)/pylib/*srm* $(prebuilt-dir)/pylib/.
	cp -R driver/gibraltar/out/$(BUILD_TYPE)/build/shared/src/nplapi/*.* $(prebuilt-dir)/build/shared/src/nplapi
	cp -R driver/gibraltar/out/$(BUILD_TYPE)/build/shared/src/nplapi/.npl* $(prebuilt-dir)/build/shared/src/nplapi
	cp -R driver/gibraltar/out/$(BUILD_TYPE)/build/shared/src/nplapi/compiled/json $(prebuilt-dir)/build/shared/src/nplapi/compiled
	cp -R driver/gibraltar/out/$(BUILD_TYPE)/build/shared/src/nplapi/compiled/python_api $(prebuilt-dir)/build/shared/src/nplapi/compiled
	cp -R driver/gibraltar/out/$(BUILD_TYPE)/build/shared/src/nplapi/compiled/api $(prebuilt-dir)/build/shared/src/nplapi/compiled
	cp -R driver/gibraltar/out/$(BUILD_TYPE)/build/shared/src/nplapi/compiled/api/json/npl_tables_locations.json $(prebuilt-dir)/build/shared/src/nplapi/compiled/api/json
	cp -R driver/gibraltar/out/$(BUILD_TYPE)/build/src/hld $(prebuilt-dir)/build/src/.
	cp -R driver/gibraltar/out/$(BUILD_TYPE)/build/src/ra/ra_translator_creator_base.h $(prebuilt-dir)/build/src/ra
	cp -R driver/gibraltar/out/$(BUILD_TYPE)/build/shared/src/nsim_provider/nsim_translator_creator_base.h $(prebuilt-dir)/build/shared/src/nsim_provider

ifeq ($(SIMULATOR), 1)
	cp -R driver/gibraltar/out/$(BUILD_TYPE)/build/shared/src/nplapi/compiled/$(NPSUITE_ARCHIVE_FILENAME) $(prebuilt-dir)/build/shared/src/nplapi/compiled/$(NPSUITE_ARCHIVE_FILENAME)
	mkdir -p $(prebuilt-dir)/npsuite
	$(PYTHON_BIN) $(NPSUITE_ROOT)/scripts/nsim_only_release.py --nsim-files $(NPSUITE_ROOT)/simulator_only_files.txt --destination $(prebuilt-dir)/npsuite
endif

	cp $(srm-include-path)/*.h $(prebuilt-dir)/include/srm
	cp $(srm-include-path)/platform/*.h $(prebuilt-dir)/include/srm/platform
	sed $(SED_ASIC_CMD) driver/Makefile > out/driver/Makefile
	sed $(SED_ASIC_CMD) -e "s/ASIC-LIST := pacific gibraltar asic4 asic3 asic5/ASIC-LIST := pacific gibraltar/g" Makefile > out/Makefile
	sed $(SED_ASIC_CMD) scripts/sim_run.sh > out/scripts/sim_run.sh
	cp -RL driver/gibraltar/test/hld out/driver/gibraltar/test/.
	mkdir -p out/driver/gibraltar/src/srm
	cp driver/gibraltar/src/srm/Makefile.inc out/driver/gibraltar/src/srm/Makefile.inc
	cp driver/gibraltar/src/srm/swig.i out/driver/gibraltar/src/srm/swig.i
	mkdir out/driver/gibraltar/shared/include/esilicon
	cp $(esilicon-include-path)/*.h out/driver/gibraltar/shared/include/esilicon/
	cp driver/gibraltar/shared/include/lld/gibraltar/* out/driver/gibraltar/shared/include/lld/
	mkdir -p out/devices/gibraltar/lbr.pd_ver_2.0/dmc/csms/data/
	cp devices/gibraltar/lbr.pd_ver_2.0/dmc/csms/data/csms_db.lbr out/devices/gibraltar/lbr.pd_ver_2.0/dmc/csms/data/
	mkdir -p out/devices/gibraltar/leaba_defined/hw_definitions/
	cp devices/gibraltar/leaba_defined/hw_definitions/npsuite_lbr.json out/devices/gibraltar/leaba_defined/hw_definitions/
	mkdir -p out/driver/gibraltar/src/hld/system/
	cp driver/gibraltar/src/hld/system/mac_pool_port.cpp out/driver/gibraltar/src/hld/system/
	cp driver/gibraltar/src/hld/state_writer.cpp out/driver/gibraltar/src/hld/
	grep -IZril -e asic3 -e asic4 -e asic5 -e asic6 -e asic7 \
$(prebuilt-dir) \
out/driver/gibraltar/shared \
out/driver/gibraltar/src/hld \
out/driver/gibraltar/test/hld \
out/devices/gibraltar/lbr.pd_ver_2.0/dmc/csms/data \
| xargs -0 -l sed -i $(SED_ASIC_CMD)
	sed -i $(SED_ASIC_CMD) out/devices/gibraltar/leaba_defined/hw_definitions/npsuite_lbr.json
	sed -i -e 's@#include "lld/asic3_tree.h"@@g' -e 's@#include "lld/asic4_tree.h"@@g' -e 's@#include "lld/asic5_tree.h"@@g' out/driver/gibraltar/shared/src/apb/serialize_config.cfg
	echo -e '\nskip-class silicon_one::d2d_iface_impl\nskip-class silicon_one::d2d_iface\n' >> out/driver/gibraltar/shared/src/lld/serialize_config.cfg
	tar cfh gibraltar-sdk-$(VERSION)-customer-src.tar \
		--transform "s,^,gibraltar-sdk-$(VERSION)-src/,S" --show-transformed-names \
		--exclude-backups \
		--exclude-vcs \
		--exclude='__pycache__' \
		--exclude='projects' \
		--exclude='driver/gibraltar/out' \
		--exclude='driver/gibraltar/examples/out' \
		--exclude='driver/gibraltar/src/srm' \
		--exclude='driver/gibraltar/shared' \
		--exclude='npl' \
		--exclude='build/out' \
		--exclude='sai/out' \
		--exclude='scripts/out' \
		--exclude='scripts/refactor' \
		--exclude='tools/out' \
		--exclude='driver/gibraltar/externals/avago' \
		--exclude='driver/gibraltar/externals/srm' \
		--exclude='driver/gibraltar/externals/esilicon' \
		--exclude='driver/gibraltar/externals/lab_env/npu/tests/av_tests_files/snake_for_tester' \
		--exclude='driver/gibraltar/externals/lab_env/global/reg_dumps' \
		--exclude='driver/gibraltar/manufacturing' \
		--exclude='driver/gibraltar/nbproject' \
		--exclude='driver/gibraltar/test/hld' \
		--exclude='sdk_cmd_file.rest_of_init.txt' \
		--exclude='*.npl' \
		--exclude='*.swp' \
		--exclude='*asic3*'\
		--exclude='*asic4*'\
		--exclude='*asic5*'\
		--exclude='*.gibraltar.patch'\
		--exclude='d2d_iface_impl.cpp'\
		--exclude='devices/gibraltar/lbr.pd_ver_2.0/unused_lbrs'\
		--exclude='debian/internal_flags.mk'\
		-- build license driver/gibraltar externals/jansson npl sai scripts devices/pacific devices/gibraltar \
		   submodules/3rd-party/packages/sai/$(sai-ver) submodules/3rd-party/packages/cereal tools debian docker Makefile.debian
	mv out gibraltar-sdk-$(VERSION)-src
	tar vf gibraltar-sdk-$(VERSION)-customer-src.tar \
		--exclude='__pycache__' \
		--exclude='*asic3*'\
		--exclude='*asic4*'\
		--exclude='*asic5*'\
		--exclude='*.gibraltar.patch'\
		--exclude='d2d_iface_impl.cpp'\
		--exclude='gibraltar-sdk-$(VERSION)-src/driver/gibraltar/shared/manufacturing' \
		--exclude='gibraltar-sdk-$(VERSION)-src/driver/gibraltar/shared/shared/src/lld' \
		--exclude='gibraltar-sdk-$(VERSION)-src/driver/gibraltar/shared/test/hw_tables/lpm/inputs' \
		--exclude='gibraltar-sdk-$(VERSION)-src/driver/gibraltar/shared/test/hw_tables/lpm/test_scaled_down_logical_lpm.cpp' \
		--exclude='gibraltar-sdk-$(VERSION)-src/driver/gibraltar/shared/test/hw_tables/lpm/test_logical_lpm_actions.cpp' \
		--exclude='gibraltar-sdk-$(VERSION)-src/driver/gibraltar/shared/test/hw_tables/lpm/customer_tables_tests' \
		--exclude='gibraltar-sdk-$(VERSION)-src/driver/gibraltar/shared/test/hw_tables/lpm/inputs/customer_tables' \
		--exclude='gibraltar-sdk-$(VERSION)-src/driver/gibraltar/shared/test/lld/test_device_simulator.cpp' \
		--exclude='gibraltar-sdk-$(VERSION)-src/driver/gibraltar/shared/src/hw_tables/*/*_asic4.*' \
		--append gibraltar-sdk-$(VERSION)-src
	gzip gibraltar-sdk-$(VERSION)-customer-src.tar

gibraltar-release-ext-src: driver-ext-src $(gibraltar-modify-files-out)
	rm -rf gibraltar-sdk-$(VERSION)-src
	rm -f gibraltar-sdk-$(VERSION)-ext-src.tar.gz
	mkdir -p out/build
	sed -e "s/export PREBUILT_DEPENDS ?= 0/export PREBUILT_DEPENDS ?= 1/" build/Makefile.top_pre > out/build/Makefile.top_pre
	mkdir -p out/driver/gibraltar/externals
	mkdir -p out/scripts
	mkdir -p out/driver/gibraltar/test
	mkdir -p $(prebuilt-dir)/include/srm/platform
	mkdir -p $(prebuilt-dir)/build/shared/src/nsim_provider
	mkdir -p $(prebuilt-dir)/build/shared/src/nplapi/compiled/api/json
	mkdir -p $(prebuilt-dir)/build/src/ra
	mkdir -p $(prebuilt-dir)/lib
	mkdir -p $(prebuilt-dir)/lib_static
	mkdir -p $(prebuilt-dir)/pylib
	cp -R driver/gibraltar/out/$(BUILD_TYPE)/res $(prebuilt-dir)
	cp -R driver/gibraltar/out/$(BUILD_TYPE)/lib/*srm* $(prebuilt-dir)/lib/.
	cp -R driver/gibraltar/out/$(BUILD_TYPE)/lib_static/*srm* $(prebuilt-dir)/lib_static/.
	cp -R driver/gibraltar/out/$(BUILD_TYPE)/pylib/*srm* $(prebuilt-dir)/pylib/.
	cp -R driver/gibraltar/out/$(BUILD_TYPE)/build/shared/src/nplapi/*.* $(prebuilt-dir)/build/shared/src/nplapi
	cp -R driver/gibraltar/out/$(BUILD_TYPE)/build/shared/src/nplapi/.npl* $(prebuilt-dir)/build/shared/src/nplapi
	cp -R driver/gibraltar/out/$(BUILD_TYPE)/build/shared/src/nplapi/compiled/json $(prebuilt-dir)/build/shared/src/nplapi/compiled
	cp -R driver/gibraltar/out/$(BUILD_TYPE)/build/shared/src/nplapi/compiled/python_api $(prebuilt-dir)/build/shared/src/nplapi/compiled
	cp -R driver/gibraltar/out/$(BUILD_TYPE)/build/shared/src/nplapi/compiled/api $(prebuilt-dir)/build/shared/src/nplapi/compiled
	cp -R driver/gibraltar/out/$(BUILD_TYPE)/build/shared/src/nplapi/compiled/api/json/npl_tables_locations.json $(prebuilt-dir)/build/shared/src/nplapi/compiled/api/json
	cp $(srm-include-path)/*.h $(prebuilt-dir)/include/srm
	cp $(srm-include-path)/platform/*.h $(prebuilt-dir)/include/srm/platform
	sed $(SED_ASIC_CMD) driver/Makefile > out/driver/Makefile
	sed $(SED_ASIC_CMD) -e "s/ASIC-LIST := pacific gibraltar asic4 asic3 asic5/ASIC-LIST := pacific gibraltar/g" Makefile > out/Makefile
	sed $(SED_ASIC_CMD) scripts/sim_run.sh > out/scripts/sim_run.sh
	cp -RL driver/gibraltar/test/hld out/driver/gibraltar/test/.
	mkdir -p out/driver/gibraltar/src/srm
	cp driver/gibraltar/src/srm/Makefile.inc out/driver/gibraltar/src/srm/Makefile.inc
	cp driver/gibraltar/src/srm/swig.i out/driver/gibraltar/src/srm/swig.i
	mkdir out/driver/gibraltar/shared/include/esilicon
	cp $(esilicon-include-path)/*.h out/driver/gibraltar/shared/include/esilicon/
	cp driver/gibraltar/shared/include/lld/gibraltar/* out/driver/gibraltar/shared/include/lld/
	mkdir -p out/devices/gibraltar/lbr.pd_ver_2.0/dmc/csms/data/
	cp devices/gibraltar/lbr.pd_ver_2.0/dmc/csms/data/csms_db.lbr out/devices/gibraltar/lbr.pd_ver_2.0/dmc/csms/data/
	mkdir -p out/devices/gibraltar/leaba_defined/hw_definitions/
	cp devices/gibraltar/leaba_defined/hw_definitions/npsuite_lbr.json out/devices/gibraltar/leaba_defined/hw_definitions/
	mkdir -p out/driver/gibraltar/src/hld/system/
	cp driver/gibraltar/src/hld/system/mac_pool_port.cpp out/driver/gibraltar/src/hld/system/
	cp driver/gibraltar/src/hld/state_writer.cpp out/driver/gibraltar/src/hld/
	grep -IZril -e asic3 -e asic4 -e asic5 -e asic6 -e asic7 \
$(prebuilt-dir) \
out/driver/gibraltar/shared \
out/driver/gibraltar/src/hld \
out/driver/gibraltar/test/hld \
out/devices/gibraltar/lbr.pd_ver_2.0/dmc/csms/data \
| xargs -0 -l sed -i $(SED_ASIC_CMD)
	sed -i $(SED_ASIC_CMD) out/devices/gibraltar/leaba_defined/hw_definitions/npsuite_lbr.json
	sed -i -e 's@#include "lld/asic3_tree.h"@@g' -e 's@#include "lld/asic4_tree.h"@@g' -e 's@#include "lld/asic5_tree.h"@@g' out/driver/gibraltar/shared/src/apb/serialize_config.cfg
	echo -e '\nskip-class silicon_one::d2d_iface_impl\nskip-class silicon_one::d2d_iface\n' >> out/driver/gibraltar/shared/src/lld/serialize_config.cfg
	tar cfh gibraltar-sdk-$(VERSION)-ext-src.tar \
		--transform "s,^,gibraltar-sdk-$(VERSION)-src/,S" --show-transformed-names \
		--exclude-backups \
		--exclude-vcs \
		--exclude='__pycache__' \
		--exclude='projects' \
		--exclude='driver/gibraltar/out' \
		--exclude='driver/gibraltar/examples/out' \
		--exclude='driver/gibraltar/src/srm' \
		--exclude='driver/gibraltar/shared' \
		--exclude='build/out' \
		--exclude='sai/out' \
		--exclude='scripts/out' \
		--exclude='scripts/refactor' \
		--exclude='tools/out' \
		--exclude='driver/gibraltar/externals/avago' \
		--exclude='driver/gibraltar/externals/srm' \
		--exclude='driver/gibraltar/externals/esilicon' \
		--exclude='driver/gibraltar/externals/lab_env/npu/tests/av_tests_files/snake_for_tester' \
		--exclude='driver/gibraltar/externals/lab_env/global/reg_dumps' \
		--exclude='driver/gibraltar/manufacturing' \
		--exclude='driver/gibraltar/nbproject' \
		--exclude='driver/gibraltar/test/hld' \
		--exclude='sdk_cmd_file.rest_of_init.txt' \
		--exclude='*.swp' \
		--exclude='*asic3*'\
		--exclude='*asic4*'\
		--exclude='*asic5*'\
		--exclude='*.gibraltar.patch'\
		--exclude='d2d_iface_impl.cpp'\
		--exclude='devices/gibraltar/lbr.pd_ver_2.0/unused_lbrs'\
		-- build license driver/gibraltar externals/jansson npl sai scripts devices/pacific devices/gibraltar README.BIN README.SRC \
		   submodules/3rd-party/packages/sai/$(sai-ver) submodules/3rd-party/packages/cereal tools
	mv out gibraltar-sdk-$(VERSION)-src
	tar vf gibraltar-sdk-$(VERSION)-ext-src.tar \
		--exclude='__pycache__' \
		--exclude='*asic3*'\
		--exclude='*asic4*'\
		--exclude='*asic5*'\
		--exclude='*.gibraltar.patch'\
		--exclude='d2d_iface_impl.cpp'\
		--exclude='gibraltar-sdk-$(VERSION)-src/driver/gibraltar/shared/manufacturing' \
		--exclude='gibraltar-sdk-$(VERSION)-src/driver/gibraltar/shared/shared/src/lld' \
		--exclude='gibraltar-sdk-$(VERSION)-src/driver/gibraltar/shared/test/hw_tables/lpm/inputs' \
		--exclude='gibraltar-sdk-$(VERSION)-src/driver/gibraltar/shared/test/hw_tables/lpm/test_scaled_down_logical_lpm.cpp' \
		--exclude='gibraltar-sdk-$(VERSION)-src/driver/gibraltar/shared/test/hw_tables/lpm/test_logical_lpm_actions.cpp' \
		--exclude='gibraltar-sdk-$(VERSION)-src/driver/gibraltar/shared/test/hw_tables/lpm/customer_tables_tests' \
		--exclude='gibraltar-sdk-$(VERSION)-src/driver/gibraltar/shared/test/hw_tables/lpm/inputs/customer_tables' \
		--exclude='gibraltar-sdk-$(VERSION)-src/driver/gibraltar/shared/test/lld/test_device_simulator.cpp' \
		--exclude='gibraltar-sdk-$(VERSION)-src/driver/gibraltar/shared/src/hw_tables/*/*_asic4.*' \
		--append gibraltar-sdk-$(VERSION)-src
	gzip gibraltar-sdk-$(VERSION)-ext-src.tar

$(PACIFIC_BIN_TARBALL) $(GIBRALTAR_BIN_TARBALL): %-sdk-$(VERSION).tar.gz:
	$(MAKE) -C driver/$* all
	$(MAKE) -C sai $*-src
	rm -rf $*-out
	rm -rf $*-sdk-$(VERSION)
	mkdir -p $*-out/driver $*-out/driver/include
	cp -LR $(NPSUITE_ROOT) $*-out/npsuite
	cp -LR driver/$*/out/$(BUILD_TYPE)/{bin,doc,lib,lib_static,pylib,res,modules} $*-out/driver
	cp -LR driver/$*/out/$(BUILD_TYPE)/include $*-out/driver
	cp -LR driver/$*/out/$(BUILD_TYPE)/build/shared/src/lld/$*_tree.h $*-out/driver/include/lld
	cp -LR driver/$*/out/$(BUILD_TYPE)/build/shared/src/lld/$*_reg_structs.h $*-out/driver/include/lld/
	cp -LR driver/$*/out/$(BUILD_TYPE)/build/shared/src/lld/$*_mem_structs.h $*-out/driver/include/lld/
	cp -LR driver/$*/examples $*-out/driver
	mkdir -p $*-out/driver/test
	cp -LR driver/$*/test/hld $*-out/driver/test
	cp -LR driver/shared/test/api $*-out/driver/test
	cp -LR driver/shared/test/board $*-out/driver/test
	cp -LR driver/shared/test/ports $*-out/driver/test
	cp -LR driver/shared/test/utils $*-out/driver/test
	cp -LR driver/shared/manufacturing $*-out/driver/manufacturing
	mkdir -p out/npl
	cp -LR npl/pacific $*-out/npl
	cp -LR npl/cisco_router $*-out/npl
	cp -LR driver/$*/out/$(BUILD_TYPE)/build/shared/src/nplapi/compiled/physical_containers $*-out/npl
	cp -LR npl/$*/leaba_defined $*-out/npl
	mkdir -p $*-out/sai
	cp -LR sai/out/$*/$(BUILD_TYPE)/{include,lib,lib_static,pylib,res} $*-out/sai
	cp CHANGES $*-out
	cp ERRATAS $*-out
	cp README.BIN $*-out
	cp build/Makefile.envsetup $*-out/driver/
	mv $*-out $*-sdk-$(VERSION)
	tar zcfh $@ \
		--exclude-backups \
		--exclude-vcs \
		--exclude='__pycache__' \
		--exclude='driver/$*/examples/out' \
		--exclude='sdk_cmd_file.rest_of_init.txt' \
		-- $*-sdk-$(VERSION)
	rm -rf $*-sdk-$(VERSION)

$(ASIC4_BIN_TARBALL) $(ASIC3_BIN_TARBALL) $(ASIC5_BIN_TARBALL): %-sdk-$(VERSION).tar.gz:
	$(MAKE) -C driver/$* all
	rm -rf $*-out
	rm -rf $*-sdk-$(VERSION)
	mkdir -p $*-out/driver $*-out/driver/include
	cp -LR $(NPSUITE_ROOT) $*-out/npsuite
	cp -LR driver/$*/out/$(BUILD_TYPE)/{bin,doc,lib,lib_static,pylib,res,modules} $*-out/driver
	cp -LR driver/$*/out/$(BUILD_TYPE)/include $*-out/driver
	cp -LR driver/$*/out/$(BUILD_TYPE)/build/shared/src/lld/$*_tree.h $*-out/driver/include/lld
	cp -LR driver/$*/out/$(BUILD_TYPE)/build/shared/src/lld/$*_reg_structs.h $*-out/driver/include/lld/
	cp -LR driver/$*/out/$(BUILD_TYPE)/build/shared/src/lld/$*_mem_structs.h $*-out/driver/include/lld/
	cp -LR driver/$*/examples $*-out/driver
	mkdir -p $*-out/driver/test
	cp -LR driver/$*/test/hld $*-out/driver/test
	cp -LR driver/shared/test/api $*-out/driver/test
	cp -LR driver/shared/test/board $*-out/driver/test
	cp -LR driver/shared/test/ports $*-out/driver/test
	cp -LR driver/shared/test/utils $*-out/driver/test
	cp -LR driver/shared/manufacturing $*-out/driver/manufacturing
	mkdir -p out/npl
	cp -LR npl/pacific $*-out/npl
	cp -LR npl/cisco_router $*-out/npl
	cp -LR driver/$*/out/$(BUILD_TYPE)/build/shared/src/nplapi/compiled/physical_containers $*-out/npl
	cp -LR devices/akpg/$*/leaba_defined $*-out/npl
	cp -LR devices/akpg/common/leaba_defined $*-out/npl
	cp CHANGES $*-out
	cp ERRATAS $*-out
	cp README.BIN $*-out
	cp build/Makefile.envsetup $*-out/driver/
	mv $*-out $*-sdk-$(VERSION)
	tar zcfh $@ \
		--exclude-backups \
		--exclude-vcs \
		--exclude='__pycache__' \
		--exclude='driver/$*/examples/out' \
		--exclude='sdk_cmd_file.rest_of_init.txt' \
		-- $*-sdk-$(VERSION)
	rm -rf $*-sdk-$(VERSION)

.PHONY: release-bin pacific-release-bin gibraltar-release-bin asic4-release-bin asic3-release-bin asic5-release-bin

pacific-release-src: $(PACIFIC_SRC_TARBALL)
gibraltar-release-src: $(GIBRALTAR_SRC_TARBALL)
asic4-release-src: $(ASIC4_SRC_TARBALL)
asic3-release-src: $(ASIC3_SRC_TARBALL)
asic5-release-src: $(ASIC5_SRC_TARBALL)

pacific-release-bin: $(PACIFIC_BIN_TARBALL)
gibraltar-release-bin: $(GIBRALTAR_BIN_TARBALL)
asic4-release-bin: $(ASIC4_BIN_TARBALL)
asic3-release-bin: $(ASIC3_BIN_TARBALL)
asic5-release-bin: $(ASIC5_BIN_TARBALL)

release-src: pacific-release-src gibraltar-release-src asic4-release-src asic3-release-src asic5-release-src
release-bin: pacific-release-bin gibraltar-release-bin asic4-release-bin asic3-release-bin asic5-release-bin

-include Makefile.debian
