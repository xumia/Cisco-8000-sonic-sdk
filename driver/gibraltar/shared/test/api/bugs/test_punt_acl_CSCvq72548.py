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
from scapy.all import *
from packet_test_utils import *
from ipv4_ingress_acl.ipv4_ingress_acl_base import *
import decor
import topology as T
import nplapicli as nplapi
import smart_slices_choise as ssch

HOST_MAC_ADDR = "fe:dc:ba:98:76:54"
PUNT_VLAN = 0xB13
PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class punt_acl(ipv4_ingress_acl_base):
    INJECT_SLICE = T.get_device_slice(3)
    INJECT_IFG = T.get_device_ifg(0)
    INJECT_PIF_FIRST = T.get_device_first_serdes(8)
    INJECT_SP_GID = 20

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_punt_acl(self):
        ssch.rechoose_odd_inject_slice(self, self.device)
        acl1 = self.create_simple_sec_acl()

        # Test default route
        self.do_test_route_default()

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [acl1])
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
        self.do_test_route_default_with_acl()

        pi_port = T.punt_inject_port(
            self,
            self.device,
            self.INJECT_SLICE,
            self.INJECT_IFG,
            self.INJECT_SP_GID,
            self.INJECT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        punt_dest = T.create_l2_punt_destination(self, self.device, T.L2_PUNT_DESTINATION2_GID, pi_port, HOST_MAC_ADDR, PUNT_VLAN)

        # Change drop to punt
        self.redirect_meter = T.create_meter_set(self, self.device, is_aggregate=True)

        self.device.set_trap_configuration(
            sdk.LA_EVENT_L3_ACL_FORCE_PUNT,
            0,
            self.redirect_meter,
            punt_dest,
            False,
            False,
            True, 0)

        # Add punt ACE
        self.insert_punt_ace(acl1)

        # Test punted packet
        punt_packet = Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
            Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
                 next_header_offset=len(Ether()) + 2 * len(Dot1Q()),
                 source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                 code=nplapi.NPL_REDIRECT_CODE_L3_ACL_FORCE_PUNT,
                 source_sp=T.RX_SYS_PORT_GID, destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                 source_lp=T.RX_L3_AC_GID, destination_lp=nplapi.NPL_REDIRECT_CODE_L3_ACL_FORCE_PUNT,
                 relay_id=T.VRF_GID, lpts_flow_type=0
                 ) / \
            INPUT_PACKET

        run_and_compare(self, self.device,
                        INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        punt_packet, self.INJECT_SLICE, self.INJECT_IFG, self.INJECT_PIF_FIRST)

        # Check counter
        packet_count, byte_count = self.punt_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        # Check meter
        packet_count, byte_count = self.redirect_meter.read(0, True, True, sdk.la_qos_color_e_GREEN)
        self.assertEqual(packet_count, 1)

        # Detach ACL
        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        # Test default route
        self.do_test_route_default()


if __name__ == '__main__':
    unittest.main()
