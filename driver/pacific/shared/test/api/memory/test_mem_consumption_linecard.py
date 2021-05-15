#!/usr/bin/env python3
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

import decor
import unittest
import decor
from mem_consumption_base import mem_consumption_base
import os

HW_EXPECTED_MEM_CONSUMPTION = 565000
SIM_EXPECTED_MEM_CONSUMPTION = 750000
LINECARD_EXPECTED_MEM_CONSUMPTION = HW_EXPECTED_MEM_CONSUMPTION if decor.is_hw_device() else SIM_EXPECTED_MEM_CONSUMPTION

# This test measures SDK memory consumption
# In case your PR caused this test to fail, you have the following options:
# 1) Fix the tests so it uses less memory
# 2) If you think your PR justifies the increase in memory consumed by SDK,
#    you have an option to increase the limit in this test. Then, during
#    code review, the reviewer will approve your change or ask you to fix
#    it according to 1).
# Please notice: the test is expected to pass only in the production environment.
# If you are compiling with different optimization level (e.g. OPT=0 instad of
# OPT=3) or you are running SDK through tools that increase the memory
# consumption, this test might fail. Ignore this.


@unittest.skip("Disable this test completely till will be reconsidered")
@unittest.skipIf(not decor.is_hw_device(), "Disable temporarily for simulation")
@unittest.skipIf(decor.is_gibraltar(), "Test is not yet enabled on GB")
@unittest.skipIf(os.environ.get("IS_VALGRIND") is not None,
                 "Test is skipped due to different memory consumption when running under Valgrind")
class test_mem_consumption_linecard(mem_consumption_base):

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_mode_lc(self):
        import sim_utils
        self._test_mem(sim_utils.LINECARD_3N_3F_DEV, LINECARD_EXPECTED_MEM_CONSUMPTION)


if __name__ == '__main__':
    unittest.main()
