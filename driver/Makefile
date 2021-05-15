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

# Disable asic3 before NPL fixed for graphehe registers
PROJECTS ?= pacific gibraltar asic4 asic3 asic5
BUILD_TYPES = test verify-format apply-format sanity ext-src customer-src clean all

.PHONY: $(PROJECTS)
all: $(PROJECTS)
$(PROJECTS): %:
	$(MAKE) -C $* all

TEST_PROJECTS = $(foreach project, $(PROJECTS), $(project)-test)
.PHONY: test $(TEST_PROJECTS)
test: $(TEST_PROJECTS)
$(TEST_PROJECTS): %-test: %
	$(MAKE) -C $* test

BENCHMARK_PROJECTS = $(foreach project, $(PROJECTS), $(project)-benchmark)
.NOTPARALLEL: benchmark
.PHONY: $(BENCHMARK_PROJECTS)
benchmark: $(BENCHMARK_PROJECTS)
$(BENCHMARK_PROJECTS): %-benchmark: %
	$(MAKE) -C $* benchmark

BENCHMARK_SAVE_PROJECTS = $(foreach project, $(PROJECTS), $(project)-benchmark-save)
.PHONY: $(BENCHMARK_SAVE_PROJECTS)
.NOTPARALLEL: benchmark-save
benchmark-save: $(BENCHMARK_SAVE_PROJECTS)
$(BENCHMARK_SAVE_PROJECTS): %-benchmark-save: %
	$(MAKE) -C $* benchmark-save

VERIFY_FORMAT_PROJECTS = $(foreach project, $(PROJECTS), $(project)-verify-format)
.PHONY: $(VERIFY_FORMAT_PROJECTS)
verify-format: $(VERIFY_FORMAT_PROJECTS)
$(VERIFY_FORMAT_PROJECTS): %-verify-format:
	$(MAKE) -C $* verify-format

APPLY_FORMAT_PROJECTS = $(foreach project, $(PROJECTS), $(project)-apply-format)
.PHONY: $(APPLY_FORMAT_PROJECTS)
apply-format: $(APPLY_FORMAT_PROJECTS)
$(APPLY_FORMAT_PROJECTS): %-apply-format:
	$(MAKE) -C $* apply-format

SANITY_PROJECTS = $(foreach project, $(PROJECTS), $(project)-sanity)
.PHONY: sanity $(SANITY_PROJECTS)
sanity: $(SANITY_PROJECTS)
$(SANITY_PROJECTS): %-sanity: %
	$(MAKE) -C $* sanity

EXT_SRC_PROJECTS = $(foreach project, $(PROJECTS), $(project)-ext-src)
.PHONY: ext-src $(EXT_SRC_PROJECTS)
ext-src: $(EXT_SRC_PROJECTS)
$(EXT_SRC_PROJECTS): %-ext-src:
	$(MAKE) -C $* ext-src

CUSTOMER_SRC_PROJECTS = $(foreach project, $(PROJECTS), $(project)-customer-src)
.PHONY: customer-src $(CUSTOMER_SRC_PROJECTS)
#customer-src: $(CUSTOMER_SRC_PROJECTS)
customer-src: gibraltar-customer-src
$(CUSTOMER_SRC_PROJECTS): %-customer-src:
	$(MAKE) -C $* customer-src

.PHONY: pacific-customer-src
pacific-customer-src:
	$(MAKE) -C pacific customer-src

CLEAN_PROJECTS = $(foreach project, $(PROJECTS), $(project)-clean)
.PHONY: clean $(CLEAN_PROJECTS)
clean: $(CLEAN_PROJECTS)
$(CLEAN_PROJECTS): %-clean:
	$(MAKE) -C $* clean

TEST_VALGRIND_PROJECTS = $(foreach project, $(PROJECTS), $(project)-test-valgrind)
.PHONY: test-valgrind $(TEST_VALGRIND_PROJECTS)
# TODO: remove. Currently disable valgrind on Gibraltar. 
#test-valgrind: $(TEST_VALGRIND_PROJECTS)
test-valgrind: pacific-test-valgrind
$(TEST_VALGRIND_PROJECTS): %-test-valgrind:
	$(MAKE) -C $* test-valgrind
##################################### Function definition
#
## Parameters:
##       $(1)    -       project name
##       $(2)    -       build type
#define PER_PROJECT_BUILD
## Create a concatenated target that invokes the project-specific build
## Example, $(1)=pacific, $(2)=all will create a target:
##       pacific-all
#.PHONY:$(1)-$(2)
#$(1)-$(2):
#	@echo Calling build=$(1) of project=$(2)
#	$(MAKE) -C $(1) $(2)
#endef
#
#
#define GLOBAL_BUILD
## Parameters:
##       $(1)    -       build type
#
## Create a build target that invokes all the project specific builds
## Example, $(1)=all, with projects= pacific, gb will create a target:
##       all: pacific-all gb-all
#.PHONY:$(1)
#$(1): $(foreach project, $(PROJECTS), $(project)-$(1))
#endef
# 
#
##################################### Make code
#
#$(foreach project, $(PROJECTS),\
#	$(foreach build_type, $(BUILD_TYPES),\
#		$(eval $(call PER_PROJECT_BUILD,$(project),$(build_type)))))
#
#$(foreach build_type, $(BUILD_TYPES),\
#	$(eval $(call GLOBAL_BUILD,$(build_type))))
