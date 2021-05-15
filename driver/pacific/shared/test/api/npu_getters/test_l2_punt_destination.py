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

from sdk_test_case_base import *
import unittest
import sim_utils
import smart_slices_choise as ssch
import decor

HOST_MAC_ADDR = T.mac_addr("fe:dc:ba:98:76:54")
PUNT_VLAN = 0xA13


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class l2_punt_destination(sdk_test_case_base):
    INJECT_SLICE = T.get_device_slice(2)  # must be an even number

    def setUp(self):
        super().setUp()
        ssch.rechoose_even_inject_slice(self, self.device)

        self.punt_dest_l2 = T.create_l2_punt_destination(
            self,
            self.device,
            T.L2_PUNT_DESTINATION2_GID,
            self.topology.inject_ports[self.INJECT_SLICE],
            HOST_MAC_ADDR.addr_str,
            PUNT_VLAN)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_punt_destination_getters(self):
        gid = self.punt_dest_l2.get_gid()
        self.assertEqual(gid, T.L2_PUNT_DESTINATION2_GID)

        mac = self.punt_dest_l2.get_mac()
        self.assertEqual(mac.flat, HOST_MAC_ADDR.hld_obj.flat)

        vlan_tag = self.punt_dest_l2.get_vlan_tag()
        self.assertEqual(vlan_tag.fields.vid, PUNT_VLAN)


if __name__ == '__main__':
    unittest.main()
