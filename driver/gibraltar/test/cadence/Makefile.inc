# BEGIN_LEGAL
#
# Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

test-cadence-prereqs := $(lld-as-dependency) | cadence

PKG := test-cadence
PKG-TARGETS := test_py
PKG-PATH := test/cadence

PKG-PY-TEST-ENV := $(NSIM_RUN_ARGS) LD_LIBRARY_PATH=$(DLIB_OUTPUT_DIR):$(LD_LIBRARY_PATH) PYTHONPATH=$(SHARED_BASE_ROOT)/test/api:$(SHARED_BASE_ROOT)/test/utils:$(PYLIB_OUTPUT_DIR) BASE_OUTPUT_DIR=$(BASE_OUTPUT_DIR)
PKG-PY-TEST-PREREQS := $(test-cadence-prereqs)

include $(MakefileTemplateRoot)/Makefile.module_vars
include $(MakefileTemplateRoot)/Makefile.module_targets

