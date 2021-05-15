#!/usr/bin/env python3
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

import unittest
from leaba import sdk
import sim_utils
import topology as T

KILO = 1000
MEGA = 1000 * KILO
GIGA = 1000 * MEGA

MIN_TM_RATE = 588 * MEGA

OVERSIZE_BURST_SIZE = 1 << 10
LEGAL_BURST_SIZES = [10, 20]


class tm_credit_scheduler_base(unittest.TestCase):

    def setUp(self):
        self.device = sim_utils.create_device(1)

        self.topology = T.topology(self, self.device, create_default_topology=False)

        # TODO: Create another device for negative tests that returns LA_STATUS_EDIFFERENT_DEVS.
        #      Disabled for now because nsim logger issue causing valgrind errors.
        #      Will enable after fixing the nsim.
        #self.device1_name = '/dev/testdev1'
        #(status, self.device1, self.nsim1) = sim_utils.create_test_device(self.device1_name, 2)
        #self.assertEqual(status, sdk.la_status_e_SUCCESS)

    def tearDown(self):
        self.device.tearDown()
        # TODO: For negative tests that returns LA_STATUS_EDIFFERENT_DEVS.
        # sim_utils.destroy_device(self.device1)
