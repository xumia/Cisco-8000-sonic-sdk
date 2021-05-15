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

from packet_test_utils import *
from scapy.all import *
import unittest
from leaba import sdk
import sim_utils
import topology as T


class phy_port:
    pass


class spa_port_mtu_base(unittest.TestCase):

    # Static members
    s_tx = [phy_port() for i in range(2)]
    s_tx[0].slice = 0
    s_tx[0].ifg = 0
    s_tx[0].first_serdes = T.get_device_first_serdes(4)
    s_tx[0].last_serdes = T.get_device_last_serdes(5)
    s_tx[1].slice = T.get_device_slice(3)
    s_tx[1].ifg = T.get_device_ifg(1)
    s_tx[1].first_serdes = T.get_device_next_first_serdes(8)
    s_tx[1].last_serdes = T.get_device_next_last_serdes(9)

    def rechoose_slices(self):
        # MATILDA_SAVE -- need review
        self.s_tx[0].slice = T.choose_active_slices(self.device, self.s_tx[0].slice, [0, 4, 2])
        self.s_tx[1].slice = T.choose_active_slices(self.device, self.s_tx[1].slice, [1, 3, 5])

    def setUp(self):
        self.device = sim_utils.create_device(1)
        self.rechoose_slices()
        self.topology = T.topology(self, self.device, create_default_topology=True)

    def tearDown(self):
        self.device.tearDown()
