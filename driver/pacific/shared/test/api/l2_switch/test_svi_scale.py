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
from l2_switch_base import l2_switch_base
import topology as T


@unittest.skipIf(True, "Temporarily disable on master")
@unittest.skipIf(not (decor.is_hw_gibraltar() or decor.is_hw_pacific()), "Test is applicable only on Pacific and Gibraltar HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class test_svi_scale(l2_switch_base):

    def test_create_4k_svi(self):

        # generate list of mac addresses
        num_mac_to_test = 4096
        mac_list = self.generate_macs("de:ed:00", num_mac_to_test)

        self.vrf = T.vrf(self, self.device, T.VRF_GID)
        self.eth_port = T.ethernet_port(self, self.device, 1, 0, 0x80, 6, 7)
        self.eth_port2 = T.ethernet_port(self, self.device, 2, 0, 0x81, 6, 7)

        for i in range(4000):
            svi_gid_base = 0x1000
            sw_gid_base = 0x1000
            ac_gid_base = 0x8000
            ac_gid_base2 = 0x9000
            #print(i, sw_gid_base + i, svi_gid_base + i, ac_gid_base + i, mac_list[0])

            sw = T.switch(self, self.device, sw_gid_base + i)
            l2ac = T.l2_ac_port(self, self.device, ac_gid_base + i, None, sw, self.eth_port, T.RX_MAC, i, 0,
                                egress_feature_mode = sdk.la_l2_service_port.egress_feature_mode_e_L3)
            l2ac2 = T.l2_ac_port(self, self.device, ac_gid_base2 + i, None, sw, self.eth_port2, T.RX_MAC, i, i,
                                 egress_feature_mode = sdk.la_l2_service_port.egress_feature_mode_e_L3)

            try:
                # Create all SVI's with same mac.
                # The test can be modified to create SVI's with different macs as well
                svi = T.svi_port(self, self.device, svi_gid_base + i, sw, self.vrf, T.mac_addr(mac_list[0]))
            except sdk.BaseException as STATUS:
                if (STATUS.args[0] != sdk.la_status_e_E_RESOURCE):
                    raise STATUS
                break

        # MYMAC EM table can hold 8K entries in case of GB and 6K entries in case of Pacific.
        # The maximum number of vlans that can be created on PC is 2615 and GB is 3794 (not 4k yet).
        if(decor.is_gibraltar()):
            self.max_svi = 3790
        if(decor.is_pacific()):
            self.max_svi = 2610

        print(i, "SVIs created")
        self.assertLess(self.max_svi, i)


if __name__ == '__main__':
    unittest.main()
