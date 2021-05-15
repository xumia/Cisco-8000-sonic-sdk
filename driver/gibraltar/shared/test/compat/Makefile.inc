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

# This module ensure compatibility with relevant user tool-chains.

include $(MakefileTemplateRoot)/Makefile.module_pre

PKG := test-compat
PKG-PATH := shared/test/compat

include $(MakefileTemplateRoot)/Makefile.module_vars

test-compat-src := $(PKG-PATH)/test.cpp
test-compat-bin := $(test-compat-build-dir)/compat.out

ifneq ($(wildcard /common/pkgs),)
    GCC47_DIR ?= /common/pkgs/gcc/4.7.0
else ifneq ($(wildcard /auto/asic-tools/sw),)
    GCC47_DIR ?= /auto/asic-tools/sw/gcc/4.7.0
endif

$(test-compat-bin): api-include $(test-compat-src)
	$(SILENT)$(MKDIR) -p $(@D)
	$(SILENT)$(GCC47_DIR)/bin/g++ -std=c++11 -I$(INCLUDE_OUTPUT_DIR) -I$(SHARED_INCLUDE_OUTPUT_DIR) -include $(INCLUDE_OUTPUT_DIR)/api/*/*.h $(test-compat-src) -o $@
	$(SILENT)echo test-compat-test passed.

test-compat-test: $(test-compat-bin)

.PHONY: test-compat-clean
test-compat-clean:
	$(SILENT)$(RM) -rf $(test-compat-bin)

clean:: test-compat-clean

