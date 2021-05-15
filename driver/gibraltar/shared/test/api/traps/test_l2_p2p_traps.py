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
class l2_p2p_trap_test(l2_p2p_trap_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_p2p_cdp_trap(self):
        TrapsTest.install_an_entry_in_copc_mac_table(
            self,
            0,
            0,
            T.mac_addr('01:00:0C:CC:CC:CC'),
            sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS,
            T.mac_addr('ff:ff:ff:ff:ff:fe'))
        self._test_drop_traffic(0, 1, 'CDP')
        TrapsTest.clear_entries_from_copc_mac_table(self)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_p2p_cdp_trap_skip(self):
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS, 0,
                                           None, None, False, True, True, 0)
        self._test_traffic(0, 1, 'CDP')

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_p2p_bcast_trap_skip(self):
        self._test_traffic(0, 1, 'BCAST')

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_p2p_std_macsec_trap_skip(self):
        TrapsTest.install_an_entry_in_copc_mac_table(
            self,
            STD_MACSEC_ETHERTYPE,
            0xffff,
            T.mac_addr(DEST_MAC),
            sdk.LA_EVENT_ETHERNET_MACSEC,
            T.mac_addr('ff:ff:ff:ff:ff:fe'), 0x00, 0xff, False, True)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_MACSEC)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_MACSEC, 0,
                                           None, None, False, True, True, 0)
        self._test_traffic(0, 1, 'MACSEC')
        TrapsTest.clear_entries_from_copc_mac_table(self)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_p2p_wan_macsec_trap_skip(self):
        TrapsTest.install_an_entry_in_copc_mac_table(
            self,
            WAN_MACSEC_ETHERTYPE,
            0xffff,
            T.mac_addr(DEST_MAC),
            sdk.LA_EVENT_ETHERNET_MACSEC,
            T.mac_addr('ff:ff:ff:ff:ff:fe'), 0x00, 0xff, False, True)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_MACSEC)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_MACSEC, 0,
                                           None, None, False, True, True, 0)
        self._test_traffic(0, 1, 'WANMACSEC')
        TrapsTest.clear_entries_from_copc_mac_table(self)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_p2p_arp_trap_skip(self):
        TrapsTest.install_an_entry_in_copc_mac_table(
            self,
            0x0806,
            0xffff,
            T.mac_addr(DEST_MAC),
            sdk.LA_EVENT_ETHERNET_ARP,
            T.mac_addr('ff:ff:ff:ff:ff:fe'), 0x00, 0xff, False, True)
        self.eth_ports[0].hld_obj.set_copc_profile(0x1)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_ARP, 0,
                                           None, None, False, True, True, 0)
        self._test_traffic(0, 1, 'ARP')
        self.eth_ports[0].hld_obj.set_copc_profile(0x0)
        TrapsTest.clear_entries_from_copc_mac_table(self)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_p2p_dhcpv4_server_trap_skip(self):
        TrapsTest.install_an_entry_in_copc_ipv4_table(
            self,
            0x11,
            0xff,
            0x43,
            0xffff,
            0x2,
            0xff,
            sdk.la_control_plane_classifier.logical_port_type_e_L2,
            0xff,
            False,
            False,
            sdk.LA_EVENT_ETHERNET_DHCPV4_SERVER,
            T.ipv4_addr('0.0.0.0'),
            T.ipv4_addr('0.0.0.0'),
            False,
            True)
        self.eth_ports[0].hld_obj.set_copc_profile(0x2)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_DHCPV4_SERVER, 0,
                                           None, None, False, True, True, 0)
        self._test_traffic(0, 1, 'DHCPV4SERVER')
        self.eth_ports[0].hld_obj.set_copc_profile(0x0)
        TrapsTest.clear_entries_from_copc_ipv4_table(self)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_p2p_dhcpv4_client_trap_skip(self):
        TrapsTest.install_an_entry_in_copc_ipv4_table(
            self,
            0x11,
            0xff,
            0x44,
            0xffff,
            0x2,
            0xff,
            sdk.la_control_plane_classifier.logical_port_type_e_L2,
            0xff,
            False,
            False,
            sdk.LA_EVENT_ETHERNET_DHCPV4_CLIENT,
            T.ipv4_addr('0.0.0.0'),
            T.ipv4_addr('0.0.0.0'),
            False,
            True)
        self.eth_ports[0].hld_obj.set_copc_profile(0x2)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_DHCPV4_CLIENT, 0,
                                           None, None, False, True, True, 0)
        self._test_traffic(0, 1, 'DHCPV4CLIENT')
        self.eth_ports[0].hld_obj.set_copc_profile(0x0)
        TrapsTest.clear_entries_from_copc_ipv4_table(self)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_p2p_dhcpv6_server_trap_skip(self):
        TrapsTest.install_an_entry_in_copc_ipv6_table(
            self,
            0x11,
            0xff,
            0x223,
            0xffff,
            0x3,
            0xff,
            sdk.la_control_plane_classifier.logical_port_type_e_L2,
            0xff,
            False,
            False,
            sdk.LA_EVENT_ETHERNET_DHCPV6_SERVER,
            T.ipv6_addr('0::0'),
            T.ipv6_addr('0::0'),
            False,
            True)
        self.eth_ports[0].hld_obj.set_copc_profile(0x3)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_DHCPV6_SERVER, 0,
                                           None, None, False, True, True, 0)
        self._test_traffic(0, 1, 'DHCPV6SERVER')
        self.eth_ports[0].hld_obj.set_copc_profile(0x0)
        TrapsTest.clear_entries_from_copc_ipv6_table(self)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_p2p_dhcpv6_client_trap_skip(self):
        TrapsTest.install_an_entry_in_copc_ipv6_table(
            self,
            0x11,
            0xff,
            0x222,
            0xffff,
            0x3,
            0xff,
            sdk.la_control_plane_classifier.logical_port_type_e_L2,
            0xff,
            False,
            False,
            sdk.LA_EVENT_ETHERNET_DHCPV6_CLIENT,
            T.ipv6_addr('0::0'),
            T.ipv6_addr('0::0'),
            False,
            True)
        self.eth_ports[0].hld_obj.set_copc_profile(0x3)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_DHCPV6_CLIENT, 0,
                                           None, None, False, True, True, 0)
        self._test_traffic(0, 1, 'DHCPV6CLIENT')
        self.eth_ports[0].hld_obj.set_copc_profile(0x0)
        TrapsTest.clear_entries_from_copc_ipv6_table(self)


if __name__ == '__main__':
    unittest.main()
