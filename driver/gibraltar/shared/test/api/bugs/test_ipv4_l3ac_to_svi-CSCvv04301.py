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
from sdk_test_case_base import *
import packet_test_utils as U
import scapy.all as S
import topology as T
import sim_utils
import ip_test_base
import sys
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_ipv4_l3ac_to_svi(sdk_test_case_base):
    ip_impl = ip_test_base.ipv4_test_base
    PRIVATE_DATA = 0x1234567890abcdef
    TTL = 64
    SA = T.mac_addr('be:ef:5d:35:7a:35')
    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')

    # Forwarding headers
    IN_DSCP = sdk.la_ip_dscp()
    IN_DSCP.value = 48

    IN_TOS = sdk.la_ip_tos()
    IN_TOS.fields.ecn = 0
    IN_TOS.fields.dscp = IN_DSCP.value

    # Intermediate qos groups
    QOS_GROUPID = 2
    DUMMY_QOS_GROUPID = 0

    # Egress QoS fields
    # Forwarding headers
    OUT_DSCP = sdk.la_ip_dscp()
    OUT_DSCP.value = 63

    OUT_TOS = sdk.la_ip_tos()
    OUT_TOS.fields.ecn = 0
    OUT_TOS.fields.dscp = OUT_DSCP.value

    ZERO_DSCP = sdk.la_ip_dscp()
    ZERO_DSCP.value = 0

    # Encapsulating headers
    OUT_PCPDEI = sdk.la_vlan_pcpdei()
    OUT_PCPDEI.fields.pcp = 5
    OUT_PCPDEI.fields.dei = 1

    INPUT_PACKET_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, tos=IN_DSCP.value << 2, ttl=TTL)

    EXPECTED_OUTPUT_PACKET_BASE = \
        S.Ether(dst=T.NH_SVI_REG_MAC.addr_str, src=T.TX_SVI_MAC.addr_str) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, tos=OUT_DSCP.value << 2, ttl=TTL - 1)

    INPUT_PACKET, EXPECTED_OUTPUT_PACKET = U.pad_input_and_output_packets(
        INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)

    def setUp(self):
        super().setUp()

    def do_test_route(self):
        self.topology.tx_l2_ac_port_reg.hld_obj.set_egress_feature_mode(sdk.la_l2_service_port.egress_feature_mode_e_L2)
        self.prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, self.prefix, self.topology.nh_svi_reg, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_SVI)

    def do_delete_route(self):
        self.ip_impl.delete_route(self.topology.vrf, self.prefix)

    def do_test_host(self):
        subnet = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_subnet(self.topology.tx_svi, subnet)
        self.ip_impl.add_host(self.topology.tx_svi, self.DIP, self.topology.nh_svi_reg.mac_addr)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_SVI)

    def do_delete_host(self):
        self.ip_impl.delete_host(self.topology.tx_svi, self.DIP)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    def test_l3ac_to_svi(self):
        # Topology default qos profiles
        ingress_qos_profile_def = self.topology.ingress_qos_profile_def
        egress_qos_profile_def = self.topology.egress_qos_profile_def

        # Create new ingress/egress qos profiles
        ingress_qos_profile_new = T.ingress_qos_profile(self, self.device)
        ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_enabled(True)

        # Topology creates egress qos profile with QOS_TAG as default marking source, so get it from the device.
        egress_qos_profile_new = self.device.create_egress_qos_profile(sdk.la_egress_qos_marking_source_e_QOS_GROUP)
        marking_source = egress_qos_profile_new.get_marking_source()
        self.assertEqual(marking_source, sdk.la_egress_qos_marking_source_e_QOS_GROUP)

        # Prepare remarking of IN_DSCP -> OUT_DSCP
        encap_qos_values_new = sdk.encapsulating_headers_qos_values()
        encap_qos_values_new.pcpdei = self.OUT_PCPDEI

        ingress_qos_profile_new.hld_obj.set_qos_group_mapping(sdk.la_ip_version_e_IPV4, self.IN_DSCP, self.QOS_GROUPID)
        ingress_qos_profile_new.hld_obj.set_qos_group_mapping(sdk.la_ip_version_e_IPV6, self.IN_DSCP, self.QOS_GROUPID)

        egress_qos_profile_new.set_qos_group_mapping_dscp(self.QOS_GROUPID, self.OUT_DSCP, encap_qos_values_new)

        # Write to the same entries in the topology qos profiles, just to make
        # sure the values don't overwrite the entries in the new profiles.
        encap_qos_values_def = sdk.encapsulating_headers_qos_values()

        ingress_qos_profile_def.hld_obj.set_qos_group_mapping(sdk.la_ip_version_e_IPV4, self.IN_DSCP, self.DUMMY_QOS_GROUPID)
        ingress_qos_profile_def.hld_obj.set_qos_group_mapping(sdk.la_ip_version_e_IPV6, self.IN_DSCP, self.DUMMY_QOS_GROUPID)

        egress_qos_profile_def.hld_obj.set_qos_group_mapping_dscp(self.QOS_GROUPID, self.ZERO_DSCP, encap_qos_values_def)

        # Assign new profiles
        rx_port = self.topology.rx_l3_ac
        rx_port.hld_obj.set_ingress_qos_profile(ingress_qos_profile_new.hld_obj)

        tx_port = self.topology.tx_l2_ac_port_reg
        tx_port.hld_obj.set_egress_qos_profile(egress_qos_profile_new)

        # Test getting the new profiles
        retrieved_ingress_profile = rx_port.hld_obj.get_ingress_qos_profile()
        self.assertEqual(retrieved_ingress_profile.this, ingress_qos_profile_new.hld_obj.this)

        retrieved_egress_profile = tx_port.hld_obj.get_egress_qos_profile()
        self.assertEqual(retrieved_egress_profile.this, egress_qos_profile_new.this)

        self.do_test_route()
        self.do_delete_route()
        self.do_test_host()
        self.do_delete_host()

        # Cleanup
        # Assign the previous profiles, in order to "un-use" the new ones.
        rx_port.hld_obj.set_ingress_qos_profile(ingress_qos_profile_def.hld_obj)
        tx_port.hld_obj.set_egress_qos_profile(egress_qos_profile_def.hld_obj)
        ingress_qos_profile_new.destroy()
        self.device.destroy(egress_qos_profile_new)


if __name__ == '__main__':
    unittest.main()
