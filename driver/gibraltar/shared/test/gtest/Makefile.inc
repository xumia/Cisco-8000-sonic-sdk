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

# General gtest settings
gtest-ver := googletest-master

gtest-base-build-dir := $(BASE_OUTPUT_DIR)/build/src/gtest

gmock-build-dir := $(BASE_OUTPUT_DIR)/build/src/gtest/$(gtest-ver)/googlemock
gtest-build-dir := $(BASE_OUTPUT_DIR)/build/src/gtest/$(gtest-ver)/googletest

gtest-configured := $(gtest-base-build-dir)/.configured

gtest-slib := $(SLIB_OUTPUT_DIR)/gtest_main.a
gmock-slib := $(SLIB_OUTPUT_DIR)/libgtest$(ARCHIVE_EXT)

# Rules for the Google gtest library
$(gtest-configured): shared/externals/googletest/$(gtest-ver).zip
	@echo Configuring the Google gtest library...
	@$(RM) -rf $(@D)
	@$(MKDIR) -p $(@D)
	@unzip -d $(gtest-base-build-dir) $<
	@touch $@
	@echo Done configuring the Google gtest library.

$(gtest-build-dir)/make/gtest_main.a: export CC +=
$(gtest-build-dir)/make/gtest_main.a: export CXX +=
$(gtest-build-dir)/make/gtest_main.a: export CXXFLAGS +=
$(gtest-build-dir)/make/gtest_main.a: $(gtest-configured)
	$(MAKE) -C $(gtest-build-dir)/make

$(gmock-build-dir)/make/gmock_main.a: export CC +=
$(gmock-build-dir)/make/gmock_main.a: export CXX +=
$(gmock-build-dir)/make/gmock_main.a: export CXXFLAGS +=
$(gmock-build-dir)/make/gmock_main.a: $(gtest-configured)
	$(MAKE) -C $(gmock-build-dir)/make

$(gtest-slib): $(gtest-build-dir)/make/gtest_main.a
	@$(MKDIR) -p $(@D)
	@echo Copying $< \-\> $@...
	@cp $< $@

$(gmock-slib): $(gmock-build-dir)/make/gmock_main.a
	$(MKDIR) -p $(@D)
	@echo Copying $< \-\> $@...
	@cp $< $@

clean-targets += clean-gtest

clean-gtest:
	@$(RM) -rf $(gtest-base-build-dir)

