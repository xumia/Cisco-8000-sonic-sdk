#!/usr/bin/env python3
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

import unittest
from l2_p2p_trap_base import *
import decor
from traps_base import *


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class l2_p2p_l2cp_trap_test(l2_p2p_trap_base):

    def install_default_l2cp_entry(self, npp_attribute):
        ether_value = U.Ethertype.LLDP.value
        ether_mask = 0xffff
        mac_lp_type_value = 0x00
        mac_lp_type_mask = 0xff
        my_mac_val = False
        my_mac_mask = True
        TrapsTest.install_an_entry_in_copc_mac_table(
            self,
            ether_value,
            ether_mask,
            T.mac_addr(L2CP_LLDP_DMAC),
            sdk.LA_EVENT_ETHERNET_L2CP0,
            T.mac_addr(L2CP_LLDP_DMAC_MASK),
            npp_attribute,
            mac_lp_type_value,
            mac_lp_type_mask,
            my_mac_val,
            my_mac_mask)

    def enable_lldp(self):
        npp_attribute = 0x1
        self.install_default_l2cp_entry(npp_attribute)
        self.eth_ports[0].hld_obj.set_copc_profile(npp_attribute)
        prof_val = self.eth_ports[0].hld_obj.get_copc_profile()
        self.assertEqual(prof_val, npp_attribute)

    def install_cfm_entry(self, npp_attribute):
        ether_value = CFM_ETHERTYPE
        ether_mask = 0xffff
        mac_lp_type_value = 0x00
        mac_lp_type_mask = 0xff
        my_mac_val = False
        my_mac_mask = True
        TrapsTest.install_an_entry_in_copc_mac_table(
            self,
            ether_value,
            ether_mask,
            T.mac_addr(L2CP_CFM_DMAC),
            sdk.LA_EVENT_ETHERNET_L2CP1,
            T.mac_addr(L2CP_CFM_DMAC_MASK),
            npp_attribute,
            mac_lp_type_value,
            mac_lp_type_mask,
            my_mac_val,
            my_mac_mask)

    def enable_cfm(self):
        npp_attribute = 0x2
        self.install_cfm_entry(npp_attribute)
        self.eth_ports[0].hld_obj.set_copc_profile(npp_attribute)
        prof_val = self.eth_ports[0].hld_obj.get_copc_profile()
        self.assertEqual(prof_val, npp_attribute)

    def tearDown(self):
        TrapsTest.clear_entries_from_copc_mac_table(self)
        super().tearDown()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_p2p_lldp_trap_skip(self):
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_L2CP0, 0, None, None, False, True, True, 0)
        self.enable_lldp()
        self._test_traffic(0, 1, 'LLDP')

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_p2p_cfm_trap_skip(self):
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_TEST_OAM_AC_MEP)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_L2CP1, 0, None, None, False, True, True, 0)
        self.enable_cfm()
        self._test_traffic(0, 1, 'CFM')


if __name__ == '__main__':
    unittest.main()
