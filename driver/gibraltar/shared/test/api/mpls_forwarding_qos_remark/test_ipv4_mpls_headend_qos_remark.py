#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

import sys
import unittest
from leaba import sdk
import ip_test_base
from scapy.all import *
import sim_utils
import topology as T
import packet_test_utils as U
from mpls_headend_qos_remark_base import *
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class ipv4_nh_to_mpls_meter_markdown_profile(mpls_headend_qos_remark_base, unittest.TestCase):
    INPUT_PACKET_BASE = Ether(dst=T.RX_L3_AC_MAC.addr_str,
                              src=mpls_headend_qos_remark_base.SA.addr_str,
                              type=U.Ethertype.QinQ.value) / U.Dot1QPrio(vlan=T.RX_L3_AC_PORT_VID1,
                                                                         type=U.Ethertype.Dot1Q.value,
                                                                         pcpdei=mpls_headend_qos_remark_base.IN_OUTER_PCPDEI.flat) / U.Dot1QPrio(vlan=T.RX_L3_AC_PORT_VID2,
                                                                                                                                                 pcpdei=mpls_headend_qos_remark_base.IN_PCPDEI.flat) / U.IPvX(ipvx='v4',
                                                                                                                                                                                                              src=mpls_headend_qos_remark_base.SIP.addr_str,
                                                                                                                                                                                                              dst=mpls_headend_qos_remark_base.DIP.addr_str,
                                                                                                                                                                                                              ttl=mpls_headend_qos_remark_base.IP_TTL,
                                                                                                                                                                                                              dscp=mpls_headend_qos_remark_base.IN_IP_DSCP.value)

    EXPECTED_OUTPUT_PACKET_MPLS_BASE = Ether(dst=T.NH_L3_AC_REG_MAC.addr_str,
                                             src=T.TX_L3_AC_REG_MAC.addr_str,
                                             type=U.Ethertype.MPLS.value) / MPLS(label=mpls_headend_qos_remark_base.LDP_LABEL.label,
                                                                                 ttl=mpls_headend_qos_remark_base.MPLS_TTL,
                                                                                 cos=mpls_headend_qos_remark_base.TAG_MPLS_TC.value) / U.IPvX(ipvx='v4',
                                                                                                                                              src=mpls_headend_qos_remark_base.SIP.addr_str,
                                                                                                                                              dst=mpls_headend_qos_remark_base.DIP.addr_str,
                                                                                                                                              ttl=mpls_headend_qos_remark_base.IP_TTL - 1,
                                                                                                                                              dscp=mpls_headend_qos_remark_base.IN_IP_DSCP.value)

    INPUT_PACKET, EXPECTED_OUTPUT_PACKET_MPLS = U.pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_MPLS_BASE)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv4_nh_to_mpls_meter_markdown_profile(self):
        # Assign new QoS profiles
        self.ingress_qos_profile_new = T.ingress_qos_profile(self, self.device)
        self.ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_enabled(True)
        self.egress_qos_profile_new = T.egress_qos_profile(self, self.device)

        encap_qos_values = sdk.encapsulating_headers_qos_values()
        encap_qos_values.pcpdei.fields.pcp = mpls_headend_qos_remark_base.IN_OUTER_PCPDEI.fields.pcp + 1
        encap_qos_values.tos.fields.dscp = mpls_headend_qos_remark_base.IN_IP_DSCP.value + 1
        encap_qos_values.tc.value = mpls_headend_qos_remark_base.TAG_MPLS_TC.value + 1
        encap_qos_values.use_for_inner_labels = False

        self.ingress_qos_profile_new.hld_obj.set_encap_qos_tag_mapping(
            sdk.la_ip_version_e_IPV4, mpls_headend_qos_remark_base.IN_IP_DSCP, mpls_headend_qos_remark_base.IN_MPLS_TC)
        self.ingress_qos_profile_new.hld_obj.set_encap_qos_tag_mapping(
            sdk.la_ip_version_e_IPV6, mpls_headend_qos_remark_base.IN_IP_DSCP, mpls_headend_qos_remark_base.IN_MPLS_TC)
        self.rx_port.hld_obj.set_ingress_qos_profile(self.ingress_qos_profile_new.hld_obj)
        self.egress_qos_profile_new.hld_obj.set_qos_tag_mapping_mpls_tc(
            mpls_headend_qos_remark_base.TAG_MPLS_TC, mpls_headend_qos_remark_base.OUT_MPLS_TC,
            encap_qos_values)
        self.tx_port.hld_obj.set_egress_qos_profile(self.egress_qos_profile_new.hld_obj)

        # Configure meter markdown profile table
        meter_markdown_gid = 0
        for profile in range(0, 1):
            meter_markdown_profile = self.device.create_meter_markdown_profile(meter_markdown_gid)
            meter_markdown_gid += 1
            for color in mpls_headend_qos_remark_base.COLOR_LST:
                self.ingress_qos_profile_new.hld_obj.set_color_mapping(
                    sdk.la_ip_version_e_IPV4, mpls_headend_qos_remark_base.IN_IP_DSCP, color)
                self.ingress_qos_profile_new.hld_obj.set_color_mapping(
                    sdk.la_ip_version_e_IPV6, mpls_headend_qos_remark_base.IN_IP_DSCP, color)
                for mpls_tc in range(0, 8):
                    from_mpls_tc_tag = sdk.la_mpls_tc()
                    from_mpls_tc_tag.value = mpls_tc
                    to_mpls_tc_tag = sdk.la_mpls_tc()
                    to_mpls_tc_tag.value = 7 - mpls_tc
                    meter_markdown_profile.set_meter_markdown_mapping_mpls_tc_encap(
                        color, from_mpls_tc_tag, to_mpls_tc_tag)
                    mpls_tc_tag = meter_markdown_profile.get_meter_markdown_mapping_mpls_tc_encap(
                        color, from_mpls_tc_tag)
                    self.assertEqual(to_mpls_tc_tag.value, mpls_tc_tag.value)

                # Program meter profile selection table
                self.ingress_qos_profile_new.hld_obj.set_meter_markdown_profile(meter_markdown_profile)
                meter_markdown_profile_new = self.ingress_qos_profile_new.hld_obj.get_meter_markdown_profile()
                self.assertEqual(meter_markdown_profile.this, meter_markdown_profile_new.this)

                U.run_and_compare(self, self.device,
                                  self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                  self.EXPECTED_OUTPUT_PACKET_MPLS, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

                packet_count, byte_count = self.egress_counter.read(sdk.la_l3_protocol_e_MPLS, True, True)
                self.assertEqual(packet_count, 1)
                U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_MPLS, byte_count)

            # Clean-up meter markdown profile table
            self.ingress_qos_profile_new.hld_obj.clear_meter_markdown_profile()
            self.device.destroy(meter_markdown_profile)


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
def setUpModule():
    mpls_headend_qos_remark_base.initialize_device()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
def tearDownModule():
    mpls_headend_qos_remark_base.destroy_device()


if __name__ == '__main__':
    unittest.main()
