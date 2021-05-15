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

PKG := sai_test
PKG-TARGETS := test_py
PKG-PATH := test/python
PKG-PYTHON-TEST-FRAMEWORK := pytest

PKG-PY-TEST-ENV := $(NSIM_RUN_ARGS) LD_LIBRARY_PATH=$(DLIB_OUTPUT_DIR):$(SDK_OUTPUT_DIR)/lib PYTHONPATH=$(OUTROOT)/$(BUILD_TYPE)/pylib:$(MakefileBaseRoot)/test/python:$(SDK_OUTPUT_DIR)/pylib:$(SDK_OUTPUT_DIR)/shared/test/api:$(SDK_OUTPUT_DIR)/shared/test/utils  BASE_OUTPUT_DIR=$(SDK_OUTPUT_DIR) RES_OUTPUT_DIR=$(OUTROOT)/$(BUILD_TYPE)/res SAI_SKIP_HOSTIF_NETDEV_CREATION=1

PKG-PY-TEST-PREREQS := $(sai-swig-dlib) $(sai-lib)

include $(MakefileTemplateRoot)/Makefile.module_vars
include $(MakefileTemplateRoot)/Makefile.module_targets

