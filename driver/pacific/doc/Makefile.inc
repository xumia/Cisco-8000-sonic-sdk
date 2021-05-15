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


doc-api-build-dir := $(BASE_OUTPUT_DIR)/build/doc/api
doc-lld-build-dir := $(BASE_OUTPUT_DIR)/build/doc/lld


doc-api-built := $(abspath $(doc-api-build-dir)/.built)
doc-lld-built := $(abspath $(doc-lld-build-dir)/.built)

doc-api-pdf := $(DOC_OUTPUT_DIR)/api/refman.pdf
doc-lld-pdf := $(DOC_OUTPUT_DIR)/lld/refman.pdf

clean-targets += doc-clean

$(doc-api-built): doc/api/Doxyfile | api-include
	@echo Building API DOXYGEN 
	@$(RM) -rf $(@D)
	@$(RM) -rf $(DOC_OUTPUT_DIR)/api/html
	@$(MKDIR) -p $(@D)
	@$(MKDIR) -p $(BASE_OUTPUT_DIR)/doc/api
	@cd doc/api && env $(PDFLATEX_ENV) LD_LIBRARY_PATH=$(GRAPHVIZ_DIR)/lib:$(LD_LIBRARY_PATH) DOC_BUILD_DIR=$(@D) BASE_OUTPUT_DIR=$(abspath $(BASE_OUTPUT_DIR)) DOT_PATH=$(DOT) $(DOXYGEN) > $(@D)/doxygen.log
	@cat $(@D)/warnings.log
	@test -f $(@D)/warnings.log && test ! -s $(@D)/warnings.log
	@$(CP) -R $(@D)/html $(DOC_OUTPUT_DIR)/api/html
	@touch $@

$(doc-lld-built): doc/lld/Doxyfile $(lld-lbrs-configured) | api-include
	@echo Building LLD DOXYGEN 
	@$(RM) -rf $(@D)
	@$(RM) -rf $(DOC_OUTPUT_DIR)/lld/html
	@$(MKDIR) -p $(@D)
	@$(MKDIR) -p $(BASE_OUTPUT_DIR)/doc/lld
	@cd doc/lld && env $(PDFLATEX_ENV) LD_LIBRARY_PATH=$(GRAPHVIZ_DIR)/lib:$(LD_LIBRARY_PATH) DOC_BUILD_DIR=$(@D) BASE_OUTPUT_DIR=$(abspath $(BASE_OUTPUT_DIR)) DOT_PATH=$(DOT) $(DOXYGEN) > $(@D)/doxygen.log
	@cat $(@D)/warnings.log 
	@test -f $(@D)/warnings.log && test ! -s $(@D)/warnings.log
	@$(CP) -R $(@D)/html $(DOC_OUTPUT_DIR)/lld/html
	@touch $@


$(doc-api-pdf): $(doc-api-built)
	@echo Building PDF $@
	@$(PDFLATEX_ENV) $(MAKE) -C $(doc-api-build-dir)/latex -i pdf  > $(doc-api-build-dir)/pdf_build.log
	@$(CP) $(doc-api-build-dir)/latex/refman.pdf $@

$(doc-lld-pdf): $(doc-lld-built)
	@echo Building PDF $@
	@$(PDFLATEX_ENV) $(MAKE) -C $(doc-lld-build-dir)/latex -i pdf > $(doc-lld-build-dir)/pdf_build.log
	@$(CP) $(doc-lld-build-dir)/latex/refman.pdf $@


clean-doc-api:
	@$(RM) -rf $(doc-api-build-dir)
	@$(RM) -rf $(DOC_OUTPUT_DIR)/api

clean-doc-lld:
	@$(RM) -rf $(doc-lld-build-dir)
	@$(RM) -rf $(DOC_OUTPUT_DIR)/lld


doc-clean: clean-doc-api clean-doc-lld 

doc-api: $(doc-api-built)
doc-api-pdf: $(doc-api-pdf)
doc-lld: $(doc-lld-built)
doc-lld-pdf: $(doc-lld-pdf)


.PHONY: docpdf
doc: doc-api doc-lld 
docpdf: doc-api-pdf

doc-test: doc-api doc-lld 
doc-sanity: doc-api doc-lld doc-api-pdf

