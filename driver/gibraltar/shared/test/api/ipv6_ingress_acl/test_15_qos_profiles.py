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
from scapy.all import *
from packet_test_utils import *
from ipv6_ingress_acl_base import *
import sim_utils
import topology as T
import logging


@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
class fifteen_qos_acls(ipv6_ingress_acl_base):
    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_fifteen_qos_acls(self):
        # 15 QoS profiles supported but, there is a default profile
        # allocated already in topology.py
        RX_L3_AC_QOS_NUM_GIDS = 14
        RX_L3_AC_QOS_GID_START = 0x860
        RX_L3_AC_QOS_VID1_START = 0x100
        RX_L3_AC_QOS_VID2_START = 0x200

        qos_profiles = []
        rx_l3_qos_acs = []
        qos_input_packets = []
        qos_acls = []
        for current_qos_index in range(0, RX_L3_AC_QOS_NUM_GIDS):
            # Set up QoS profiles
            qos_profiles.append(T.ingress_qos_profile(self, self.device))
            qos_profiles[current_qos_index].set_default_values()

            # Create new L3 AC ports
            temp_ac = T.l3_ac_port(self, self.device,
                                   (RX_L3_AC_QOS_GID_START + current_qos_index),
                                   self.topology.rx_eth_port,
                                   self.topology.vrf,
                                   T.RX_L3_AC_MAC,
                                   (RX_L3_AC_QOS_VID1_START + current_qos_index),
                                   (RX_L3_AC_QOS_VID2_START + current_qos_index),
                                   qos_profiles[current_qos_index])

            rx_l3_qos_acs.append(temp_ac)
            rx_l3_qos_acs[current_qos_index].hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
            rx_l3_qos_acs[current_qos_index].hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)

            # Set up input packets
            input_packet_base = Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=Ethertype.QinQ.value) / \
                Dot1Q(vlan=RX_L3_AC_QOS_VID1_START + current_qos_index, type=Ethertype.Dot1Q.value) / \
                Dot1Q(vlan=RX_L3_AC_QOS_VID2_START + current_qos_index) / \
                IPv6(src=self.SIP.addr_str, dst=self.DIP.addr_str, hlim=self.TTL) / \
                TCP()
            qos_input_packets.append(add_payload(input_packet_base, self.INPUT_PACKET_PAYLOAD_SIZE))

            # Create 14 ACLs,there is a default profile created in l3_ac_port already
            # add NOP to the first and DROP to the second. Attach the second to the port.
            qos_acls.append(self.create_simple_qos_acl())

        # Check L3 AC ports with traffic without QoS attached
        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0}}
        for current_qos_index in range(0, RX_L3_AC_QOS_NUM_GIDS):
            run_and_compare_inner_fields(self, self.device,
                                         qos_input_packets[current_qos_index], T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                         self.EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                                         control_expected)

        logging.debug("Initial packet tests on {num} ACs passed".format(num=RX_L3_AC_QOS_NUM_GIDS))

        # Attach a Q counter
        q_counters = []
        p_counters = []
        for current_qos_index in range(0, RX_L3_AC_QOS_NUM_GIDS):
            # Attach a Q counter
            q_counter = self.device.create_counter(8)
            rx_l3_qos_acs[current_qos_index].hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_QOS, q_counter)
            q_counters.append(q_counter)

            # Attach a P counter
            p_counter = self.device.create_counter(1)
            rx_l3_qos_acs[current_qos_index].hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, p_counter)
            p_counters.append(p_counter)

            # Attach the QoS ACL
            ipv6_acls = []
            ipv6_acls.append(qos_acls[current_qos_index])
            acl_group = []
            acl_group = self.device.create_acl_group()
            acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, ipv6_acls)
            rx_l3_qos_acs[current_qos_index].hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0x1F}}
        expected_output_packet = self.EXPECTED_DEFAULT_OUTPUT_PACKET.copy()
        expected_output_packet[IPv6].tc = (QOS_MARK_DSCP << 2)
        for current_qos_index in range(0, RX_L3_AC_QOS_NUM_GIDS):
            logging.debug("Verifying packet on AC {num} after QoS ACL attached".format(num=current_qos_index))
            run_and_compare_inner_fields(self, self.device,
                                         qos_input_packets[current_qos_index], T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                         expected_output_packet, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                                         control_expected)
            # Verify Q counter
            packet_count, byte_count = q_counters[current_qos_index].read(SIMPLE_QOS_COUNTER_OFFSET, True, True)
            logging.debug("Q {num}: packet: {pkt}, byte: {byte}".format(num=current_qos_index, pkt=packet_count, byte=byte_count))
            self.assertEqual(packet_count, 1)
            assertPacketLengthIngress(self, self.INPUT_PACKET, T.RX_SLICE, byte_count)

            # Verify P counter
            packet_count, byte_count = p_counters[current_qos_index].read(0, True, True)
            logging.debug("P {num}: packet: {pkt}, byte: {byte}".format(num=current_qos_index, pkt=packet_count, byte=byte_count))
            self.assertEqual(packet_count, 1)

        # Pass packet with no ACL applied, ensure PHB remains default (0).
        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0}}
        for current_qos_index in range(0, RX_L3_AC_QOS_NUM_GIDS):
            # Detach ACL
            rx_l3_qos_acs[current_qos_index].hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)
            logging.debug("Verifying packet on AC {num} after QoS ACL detached".format(num=current_qos_index))

            run_and_compare_inner_fields(self, self.device,
                                         qos_input_packets[current_qos_index], T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                         self.EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF,
                                         control_expected)


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.ERROR,
        format='%(levelname)-8s | %(asctime)s |\
                %(module)s:%(lineno)-6s | %(message)s',
    )

    unittest.main()
