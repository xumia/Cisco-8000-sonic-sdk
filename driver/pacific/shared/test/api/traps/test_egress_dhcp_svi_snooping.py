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


import decor
import unittest
from leaba import sdk
import packet_test_utils as U
import sim_utils
import topology as T

from scapy.config import conf
conf.ipv6_enabled = False
from scapy.all import *

from sdk_test_case_base import sdk_test_case_base
import ip_test_base


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class Egress_dhcp_svi_snooping(sdk_test_case_base):
    SA = T.mac_addr('be:ef:5d:35:7a:35')
    PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"
    HOST_MAC_ADDR = "fe:dc:ba:98:76:54"

    PUNT_VLAN = 0xA13

    SYS_PORT_GID_BASE = 0x123

    PI_SP_GID = SYS_PORT_GID_BASE + 2
    PI_SLICE = T.get_device_slice(2)
    PI_IFG = T.get_device_ifg(1)
    PI_PIF_FIRST = T.get_device_first_serdes(8)

    TTL = 128
    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')

    IPV4_INPUT_PACKET_BASE = \
        Ether(dst=T.RX_SVI_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
        UDP(sport=0x44, dport=0x43) / \
        BOOTP(ciaddr = '0.0.0.0', xid = 0x01020304, flags= 1) / \
        DHCP(options=[("message-type", "discover"), "end"])

    IPV4_INPUT_PACKET, __ = U.enlarge_packet_to_min_length(IPV4_INPUT_PACKET_BASE)

    PUNT_PACKET = \
        Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
        Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
        U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_IPV4,
               fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
               next_header_offset=0,
               source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_EGRESS_TRAP,
               code=sdk.LA_EVENT_ETHERNET_SVI_EGRESS_DHCP,
               source_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
               destination_sp =T.RX_SYS_PORT_GID + 2,
               source_lp=T.RX_SVI_GID,
               destination_lp=T.TX_SVI_GID,
               relay_id=T.VRF_GID,
               lpts_flow_type=0) / \
        IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1, chksum=0x6f7d) / \
        UDP(sport=0x44, dport=0x43) / \
        BOOTP(ciaddr = '0.0.0.0', xid = 0x01020304, flags= 1) / \
        DHCP(options=[("message-type", "discover"), "end"])

    def test_egress_dhcp_svi_snooping(self):
        self.pi_port = T.punt_inject_port(
            self,
            self.device,
            self.PI_SLICE,
            self.PI_IFG,
            self.PI_SP_GID,
            self.PI_PIF_FIRST,
            self.PUNT_INJECT_PORT_MAC_ADDR)
        self.punt_dest = T.create_l2_punt_destination(
            self,
            self.device,
            T.L2_PUNT_DESTINATION2_GID,
            self.pi_port,
            self.HOST_MAC_ADDR,
            self.PUNT_VLAN)

        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_SVI_EGRESS_DHCP, 0, None, self.punt_dest, False, False, True, 0)

        ip_impl = ip_test_base.ipv4_test_base
        subnet = ip_impl.build_prefix(self.DIP, length=16)
        ip_impl.add_subnet(self.topology.tx_svi, subnet)
        ip_impl.add_host(self.topology.tx_svi, self.DIP, T.NH_SVI_DEF_MAC)
        self.topology.tx_svi.hld_obj.set_egress_dhcp_snooping_enabled(True)
        enabled = self.topology.tx_svi.hld_obj.get_egress_dhcp_snooping_enabled()
        self.assertEqual(enabled, True)

        U.run_and_compare(self, self.device,
                          self.IPV4_INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        ip_impl.delete_host(self.topology.tx_svi, self.DIP)
        ip_impl.delete_subnet(self.topology.tx_svi, subnet)


if __name__ == '__main__':
    unittest.main()
