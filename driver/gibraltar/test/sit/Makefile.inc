# BEGIN_LEGAL
#
# Copyright (c) 2015-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

test-sit-prereqs := $(test-nsim-provider-swig-dlib) $(test-lld-swig-dlib) $(nplapi-swig-dlib) $(test-hld-swig-dlib) $(hld-swig-dlib) | api

PKG := test-sit
PKG-TARGETS := test_py
PKG-PATH := test/sit

include $(MakefileTemplateRoot)/Makefile.module_vars

testing-framework-dir := ../../fishnet/

test-sit-passed := $(test-sit-build-dir)/sit.passed

$(test-sit-passed): ERR-LOG = $(test-sit-build-dir)/sit.test.log
$(test-sit-passed): $(test-sit-prereqs)
	$(SILENT)echo "Sit Testing $$(basename $${PWD}) $< ..."
	$(SILENT)$(MKDIR) -p $(@D)
	$(SILENT)mkdir -p $(dir $(ERR-LOG)) ; \
	    rm -rf $(ERR-LOG) ; \
	    echo "env $(NSIM_RUN_ARGS) LD_LIBRARY_PATH=$(DLIB_OUTPUT_DIR) PYTHONPATH=$(testing-framework-dir):$(DLIB_OUTPUT_DIR):shared/test/api:shared/test/utils:test/hld:$(PYLIB_OUTPUT_DIR) BASE_OUTPUT_DIR=$(BASE_OUTPUT_DIR) $(PYTEST_BIN) $(testing-framework-dir) --sim -m sanity --junit-xml=$(test-sit-build-dir)/junit.xml" > $(ERR-LOG)
	$(SILENT)env $(NSIM_RUN_ARGS) LD_LIBRARY_PATH=$(DLIB_OUTPUT_DIR) PYTHONPATH=$(testing-framework-dir):$(DLIB_OUTPUT_DIR):shared/test/api:shared/test/utils:test/hld:$(PYLIB_OUTPUT_DIR) BASE_OUTPUT_DIR=$(BASE_OUTPUT_DIR) $(PYTEST_BIN) $(testing-framework-dir) --sim -m sanity --junit-xml=$(test-sit-build-dir)/junit.xml &>> $(ERR-LOG) || ( \
	    echo "$$$$: ERROR_LOG $$(basename $${PWD}) $(ERR-LOG)" ; \
	    cat $(ERR-LOG) | sed "s/^/$$$$: /" ; \
	    exit 1 )
	$(SILENT)rm -rf $(ERR-LOG) ; \
	    rm -rf $@; \
	    echo "env $(NSIM_RUN_ARGS) LD_LIBRARY_PATH=$(DLIB_OUTPUT_DIR) PYTHONPATH=$(testing-framework-dir):$(DLIB_OUTPUT_DIR):shared/test/api:shared/test/utils:test/hld:$(PYLIB_OUTPUT_DIR) BASE_OUTPUT_DIR=$(BASE_OUTPUT_DIR) $(PYTEST_BIN) $(testing-framework-dir) --sim -m sanity --junit-xml=$(test-sit-build-dir)/junit.xml" > $@

test-sit-clean:
	$(SILENT)rm -rf $(test-sit-passed)

test-sit-test: $(test-sit-passed)
test-sit: $(test-sit-prereqs)

clean:: test-sit-clean

