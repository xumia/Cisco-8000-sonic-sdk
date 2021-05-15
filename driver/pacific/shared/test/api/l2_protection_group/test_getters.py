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

import decor
import unittest
from leaba import sdk
import sim_utils
import topology as T
from l2_protection_group_base import *
from packet_test_utils import *
from scapy.all import *
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class l2_protection_group_getters(l2_protection_group_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_protection_group_getters(self):
        self.create_network_topology()

        primary_port = self.m_l2_protection_group.get_primary_destination()
        self.assertEqual(primary_port.this, self.m_tx_primary_port.hld_obj.this)

        protecting_port = self.m_l2_protection_group.get_backup_destination()
        self.assertEqual(protecting_port.this, self.m_tx_protecting_port.hld_obj.this)

        protection_monitor = self.m_l2_protection_group.get_monitor()
        self.assertEqual(protection_monitor.this, self.m_protection_monitor.this)

        l2_protection_group_by_id = self.device.get_l2_protection_group_by_id(self.l2_protection_group_gid)
        self.assertEqual(l2_protection_group_by_id.this, self.m_l2_protection_group.this)


if __name__ == '__main__':
    unittest.main()
