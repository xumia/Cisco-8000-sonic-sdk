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


import unittest
from leaba import sdk
from sim_utils import *


class unit_test(unittest.TestCase):
    def setUp(self):
        self.device = create_device(1)

    def tearDown(self):
        self.device.tearDown()

    def test_clear_trap_config(self):

        c0 = self.device.create_counter(1)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR,
                                           0,    # priority
                                           c0,
                                           None,  # destination
                                           True,  # skip_inject_up_packets (don't care)
                                           False,  # skip_p2p packets
                                           True,  # overwrite_phb packets
                                           0)    # tc (don't care)

        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR)

        self.device.destroy(c0)

        c1 = self.device.create_counter(1)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_SA_DA_ERROR,
                                           0,    # priority
                                           c1,
                                           None,  # destination
                                           True,  # skip_inject_up_packets (don't care)
                                           False,  # skip_p2p packets
                                           True,  # overwrite_phb packets
                                           0)    # tc (don't care)


if __name__ == '__main__':
    unittest.main()
