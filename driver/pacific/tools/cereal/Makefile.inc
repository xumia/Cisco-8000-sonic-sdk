# BEGIN_LEGAL
#
# Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

# General gtest settings
CEREAL_VERSION ?= 1.3.0

cereal-base-build-dir := $(BASE_OUTPUT_DIR)/build/tools/cereal

cereal-configured := $(cereal-base-build-dir)/.configured
cereal-include-path := $(cereal-base-build-dir)/cereal-$(CEREAL_VERSION)/include

ifeq ($(ROOT_3RD_PARTY_PKGS_DIR),)
    ifeq ($(CEREAL_ROOT_DIR),)
        $(error both ROOT_3RD_PARTY_PKGS_DIR and CEREAL_ROOT_DIR are not defined!)
    endif
endif

ifeq ($(CEREAL_ROOT_DIR),)
    CEREAL_ROOT_DIR := $(ROOT_3RD_PARTY_PKGS_DIR)/cereal
endif


# Rules for unpacking cereal
$(cereal-configured): $(CEREAL_ROOT_DIR)/v$(CEREAL_VERSION).tar.gz
	@echo Configuring the cereal library...
	@$(RM) -rf $(@D)
	@$(MKDIR) -p $(@D)
	@tar zxvf $< -C $(cereal-base-build-dir)
	@touch $@
	@echo Done configuring the cereal library.

.PHONY: cereal
cereal: $(cereal-configured)

clean-targets += clean-cereal

clean-cereal:
	@$(RM) -rf $(cereal-build-dir)

