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

from packet_test_utils import *
from scapy.all import *
import unittest
from leaba import sdk
import sim_utils
import topology as T
from sdk_test_case_base import sdk_test_case_base
import nplapicli as nplapi
import decor

MC_GROUP_ADDR = T.ipv6_addr('ff31:0:0:0:0:1:ffe8:658f')
SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
SIP3 = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:3333')
SA = T.mac_addr('be:ef:6e:35:7a:35')
TTL = 127
MC_GROUP_GID = 0x13


def get_mc_sa_addr_str(ip_addr):
    # https://tools.ietf.org/html/rfc2464#section-7
    shorts = ip_addr.addr_str.split(':')
    assert(len(shorts) == T.ipv6_addr.NUM_OF_SHORTS)
    sa_addr_str = '33:33'
    for s in shorts[-2:]:
        sl = int(s, 16) & 0xff
        sh = (int(s, 16) >> 8) & 0xff
        sa_addr_str += ':%02x:%02x' % (sh, sl)
    return sa_addr_str


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_compressed_ipv6_sip_index_handling_CSCvs06975(sdk_test_case_base):

    INPUT_PACKET_BASE3 = \
        Ether(dst=get_mc_sa_addr_str(MC_GROUP_ADDR), src=SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IPv6(src=SIP3.addr_str, dst=MC_GROUP_ADDR.addr_str, hlim=TTL, plen=40) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_BASE3 = \
        Ether(dst=get_mc_sa_addr_str(MC_GROUP_ADDR), src=T.TX_L3_AC_REG_MAC.addr_str) / \
        IPv6(src=SIP3.addr_str, dst=MC_GROUP_ADDR.addr_str, hlim=TTL - 1, plen=40) / TCP() / Raw(load=RAW_PAYLOAD)

    INPUT_PACKET3, EXPECTED_OUTPUT_PACKET3 = pad_input_and_output_packets(INPUT_PACKET_BASE3, EXPECTED_OUTPUT_PACKET_BASE3)

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_default_compressed_index(self):
        self.l3_port_impl = T.ip_l3_ac_base(self.topology)

        self.l3_port_impl.rx_port.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)

        self.mc_group = self.device.create_ip_multicast_group(MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)
        self.mc_group.add(self.l3_port_impl.tx_port.hld_obj, None, self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj)
        self.mc_group.add(self.l3_port_impl.tx_port_def.hld_obj, None, self.topology.tx_l3_ac_eth_port_def.sys_port.hld_obj)

        self.topology.vrf.hld_obj.add_ipv6_multicast_route(
            SIP.hld_obj, MC_GROUP_ADDR.hld_obj, self.mc_group, None, False, False, None)

        run_and_drop(self, self.device, self.INPUT_PACKET3, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # Cleanup
        self.topology.vrf.hld_obj.delete_ipv6_multicast_route(SIP.hld_obj, MC_GROUP_ADDR.hld_obj)

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_compressed_index_leak(self):
        self.l3_port_impl = T.ip_l3_ac_base(self.topology)

        self.l3_port_impl.rx_port.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)

        self.mc_group = self.device.create_ip_multicast_group(MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)
        self.mc_group.add(self.l3_port_impl.tx_port.hld_obj, None, self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj)
        self.mc_group.add(self.l3_port_impl.tx_port_def.hld_obj, None, self.topology.tx_l3_ac_eth_port_def.sys_port.hld_obj)

        self.topology.vrf.hld_obj.add_ipv6_multicast_route(
            SIP.hld_obj, MC_GROUP_ADDR.hld_obj, self.mc_group, None, False, False, None)

        self.topology.vrf.hld_obj.modify_ipv6_multicast_route(SIP.hld_obj, MC_GROUP_ADDR.hld_obj,
                                                              self.mc_group, None, False, False, None)

        self.topology.vrf.hld_obj.delete_ipv6_multicast_route(SIP.hld_obj, MC_GROUP_ADDR.hld_obj)

        # Ensure entry in IPv6 compressed SIP table is removed
        self.assertEquals(len(self.device.get_device_tables().ipv6_sip_compression_table[0].entries(1)), 0)


if __name__ == '__main__':
    unittest.main()
