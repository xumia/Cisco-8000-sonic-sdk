#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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


# Verify that the CEM is accessible after live soft-reset

import unittest
import decor


@unittest.skipUnless(decor.is_hw_device(), "Requires HW device")
class unit_test(unittest.TestCase):

    def setUp(self):
        import sim_utils
        import topology as T
        self.device = sim_utils.create_device(1)
        self.topology = T.topology(self, self.device)

    def tearDown(self):
        self.device.tearDown()

    def test_cem_after_soft_reset(self):
        self.device.soft_reset()

        # create_switch accesses a table in CEM
        self.device.create_switch(10)


if __name__ == '__main__':
    unittest.main()
