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

PYTHON_DIR ?= /common/pkgs/python/3.6.10
PYTHON_BIN=$(PYTHON_DIR)/bin/pytest

PY-TEST-ENV := LD_LIBRARY_PATH=$(SDK_ROOT)/lib:/common/pkgs/gcc/4.9.4/lib64:$(FISHNET)/lib:$(NPSUITE)/lib:/common/pkgs/libffi-5/ PYTHONPATH=$(SDK_ROOT)/lib:/common/pkgs/libffi-5/:test/api:test/api/snake:test/board:examples/sanity:$(SDK_ROOT)/pylib:$(SDK_ROOT)/test/hld:$(SDK_ROOT)/test/board:$(FISHNET):$(FISHNET)/init:$(FISHNET)/utils:$(FISHNET)/utils/spirent:test/utils:/cad/leaba/BSP/current/blacktip BASE_OUTPUT_DIR=$(SDK_ROOT) SDK_DEVICE_NAME='/dev/uio0'
BASE-TEST-DIR = test/board

.PHONY: build clean

build:
	env $(PY-TEST-ENV) $(PYTHON_BIN) $(BASE-TEST-DIR) --junit-xml=junit.xml

clean:
	rm -f junit.xml


