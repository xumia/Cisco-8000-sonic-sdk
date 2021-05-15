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
import scapy.all as S
import packet_test_utils as U


class qos_group_remark_dscp(unittest.TestCase):

    IN_DSCP_VAL = 0
    OUT_DSCP_VAL = 8
    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')
    PRIVATE_DATA = 0x1234567890abcdef
    TTL = 128
    SA = T.mac_addr('be:ef:5d:35:7a:35')

    # Ingress QoS fields
    IN_DSCP = sdk.la_ip_dscp()
    IN_DSCP.value = IN_DSCP_VAL
    # Egress QoS fields
    OUT_DSCP = sdk.la_ip_dscp()
    OUT_DSCP.value = OUT_DSCP_VAL

    QOS_GROUPID = 1

    INPUT_PACKET_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL)

    EXPECTED_OUTPUT_PACKET_BASE = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1, tos=(OUT_DSCP_VAL << 2))

    INPUT_PACKET, EXPECTED_OUTPUT_PACKET = U.pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)

    def setUp(self):
        self.device = U.sim_utils.create_device(1)
        self.create_network_topology()

    def tearDown(self):
        self.device.tearDown()

    def create_network_topology(self):
        self.topology = T.topology(self, self.device, create_default_topology=True)

        # Update qos profiles
        self.ingress_qos_profile = T.ingress_qos_profile(self, self.device)
        self.ingress_qos_profile.hld_obj.set_qos_group_mapping(sdk.la_ip_version_e_IPV4, self.IN_DSCP, self.QOS_GROUPID)
        self.ingress_qos_profile.hld_obj.set_qos_group_mapping(sdk.la_ip_version_e_IPV6, self.IN_DSCP, self.QOS_GROUPID)

        self.egress_qos_profile = T.egress_qos_profile(self, self.device, sdk.la_egress_qos_marking_source_e_QOS_GROUP)
        encap_qos_values = sdk.encapsulating_headers_qos_values()
        self.egress_qos_profile.hld_obj.set_qos_group_mapping_dscp(self.QOS_GROUPID, self.OUT_DSCP, encap_qos_values)

        self.topology.tx_l3_ac_reg.hld_obj.set_egress_qos_profile(self.egress_qos_profile.hld_obj)
        self.topology.rx_l3_ac.hld_obj.set_ingress_qos_profile(self.ingress_qos_profile.hld_obj)

        # add route
        prefix = sdk.la_ipv4_prefix_t()
        prefix.addr.s_addr = self.DIP.to_num() & 0xffff0000
        prefix.length = 16
        self.topology.vrf.hld_obj.add_ipv4_route(prefix, self.topology.fec_l3_ac_reg.hld_obj, self.PRIVATE_DATA, False)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_qos_group_remark_dscp(self):
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)


if __name__ == '__main__':
    unittest.main()
