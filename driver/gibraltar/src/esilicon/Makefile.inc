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

PKG := esilicon
PKG-TARGETS := libs
PKG-PATH := src/esilicon

include $(MakefileTemplateRoot)/Makefile.module_vars

# General definitions
vendor-esilicon-ver := 20190517

vendor-esilicon-build-dir := $(esilicon-build-dir)/$(vendor-esilicon-ver)
vendor-esilicon-configured := $(vendor-esilicon-build-dir)/.configured
vendor-esilicon-include-dir := $(vendor-esilicon-build-dir)/ts_7ff_hbm2llhbmphy_ins_ccode_v1p2_$(vendor-esilicon-ver)/c-code/c-code-setup/
ifeq ($(PREBUILT_DEPENDS), 1)
vendor-esilicon-tarball :=
vendor-esilicon-extract-cmd := /bin/true
else
vendor-esilicon-tarball := externals/esilicon/ts_7ff_hbm2llhbmphy_ins_ccode_v1p2_$(vendor-esilicon-ver).tar.gz
vendor-esilicon-extract-cmd := tar zxf $(vendor-esilicon-tarball) -C
endif

PKG-COMPILE-PREREQS := $(vendor-esilicon-configured)

$(PKG)-as-dependency := $($(PKG)-as-dependency) $(vendor-esilicon-configured)

include $(MakefileTemplateRoot)/Makefile.module_targets

# Rules for the eSilicon library
vendor-esilicon-configured: $(vendor-esilicon-configured)

$(vendor-esilicon-configured): $(vendor-esilicon-tarball)
	@echo Extracting eSilicon library
	@$(RM) -rf $(@D)
	@$(MKDIR) -p $(@D)
	@$(vendor-esilicon-extract-cmd) $(@D)
	@touch $@
	@echo Done configuring the eSilicon library.

