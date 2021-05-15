#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

from ipv4_ecmp_routing_base import *
import ip_test_base
import decor
import unittest
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import topology as T


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class load_balancing_node_id(ipv4_ecmp_routing_base):

    LOAD_BALANCING_ID = 0x3
    OUTPUT_TRESHOLD_PCT = 20  # Below this treshold it is considered that path is neglected in LB

    def setUp(self):
        super().setUp()

        self.topology.create_topology()
        self.topology.topology_created = True

        DIP = T.ipv4_addr('111.111.111.111')
        SIP = T.ipv4_addr('155.24.162.37')
        self.EXT_MAC = T.mac_addr('be:be:be:be:be:be')
        TTL = 128

        self.INPUT_PACKET_BASE = \
            S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=self.EXT_MAC.addr_str, type=U.Ethertype.QinQ.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL) / \
            S.TCP(sport=0x63, dport=0x64)

        EXPECTED_OUTPUT_PACKET_BASE = \
            S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=TTL - 1) / \
            S.TCP(sport=0x63, dport=0x64)
        self.EXPECTED_OUTPUT_PACKET = U.add_payload(EXPECTED_OUTPUT_PACKET_BASE, self.PAYLOAD_SIZE)

    def test_load_balancing_node_id(self):
        self.add_default_route()

        self.device.device.set_load_balancing_node_id(self.LOAD_BALANCING_ID)
        self.assertEqual(self.device.device.get_load_balancing_node_id(), self.LOAD_BALANCING_ID)

        input_packet = U.add_payload(self.INPUT_PACKET_BASE, self.PAYLOAD_SIZE)

        expected_packet, out_slice, out_ifg, out_pif = self.calculate_expected_output(input_packet)
        U.run_and_compare(self, self.device,
                          input_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          expected_packet, out_slice, out_ifg, out_pif)

        self.destroy_default_route()

    def add_default_route(self, ecmp_group):
        PRIVATE_DATA = 0x1234567890abcdef
        self.ip_impl = ip_test_base.ipv4_test_base
        prefix = self.ip_impl.get_default_prefix()
        self.topology.vrf.hld_obj.add_ipv4_route(prefix, ecmp_group, PRIVATE_DATA, False)
        self.has_default_route = True

    def destroy_default_route(self):
        if self.has_default_route:
            prefix = self.ip_impl.get_default_prefix()
            self.ip_impl.delete_route(self.topology.vrf, prefix)
            self.has_default_route = False

    def calculate_expected_output_ecmp(self, input_packet, ecmp_group):
        dip = T.ipv4_addr(input_packet[S.IP].dst)
        sip = T.ipv4_addr(input_packet[S.IP].src)

        lb_vec = sdk.la_lb_vector_t()
        lb_vec.type = sdk.LA_LB_VECTOR_IPV4_TCP_UDP
        lb_vec.ipv4.sip = sip.hld_obj.s_addr
        lb_vec.ipv4.dip = dip.hld_obj.s_addr
        lb_vec.ipv4.protocol = input_packet[S.IP].proto
        lb_vec.ipv4.src_port = input_packet[S.TCP].sport
        lb_vec.ipv4.dest_port = input_packet[S.TCP].dport

        lb_vec_entry_list = []
        lb_vec_entry_list.append(lb_vec)

        out_dest_chain = self.device.get_forwarding_load_balance_chain(ecmp_group, lb_vec_entry_list)

        # For Debug purpose:
        #U.display_forwarding_load_balance_chain(ecmp_group, out_dest_chain)

        self.assertEqual(out_dest_chain[-1].type(), sdk.la_object.object_type_e_SYSTEM_PORT)
        # find the NH in the chain
        nh_obj = None
        for e in reversed(out_dest_chain):
            if e.type() == sdk.la_object.object_type_e_NEXT_HOP:
                nh_obj = e
                break
        assert nh_obj is not None, 'No next hop in chain'

        out_nh = nh_obj.downcast()

        self.assertEqual(out_dest_chain[-1].type(), sdk.la_object.object_type_e_SYSTEM_PORT)
        out_dsp = out_dest_chain[-1].downcast()

        dst = out_nh.get_mac()
        src = out_nh.get_router_port().downcast().get_mac()
        dst_str = T.mac_addr.mac_num_to_str(dst.flat)
        src_str = T.mac_addr.mac_num_to_str(src.flat)

        new_eth_hdr = S.Ether(dst=dst_str, src=src_str)
        expected_packet = new_eth_hdr / self.EXPECTED_OUTPUT_PACKET

        out_slice = out_dsp.get_slice()
        out_ifg = out_dsp.get_ifg()
        out_pif = out_dsp.get_base_serdes()

        return expected_packet, out_slice, out_ifg, out_pif

    def is_any_dst_under_treshold(self, input_packets, output_distribution, num_of_packets):
        overloaded_path_exist = False
        for v in output_distribution.values():
            dst_cnt = len(v)
            if (dst_cnt < num_of_packets * self.OUTPUT_TRESHOLD_PCT / 100):
                return True

        return False

    def print_distribution(self, distr, message=""):
        print(message)
        for key, value in distr.items():
            print("[", key, " : ", len(value), "]")

    def do_run_and_get_distribution_ecmp(self, input_packets, ecmp_group):
        """ Runs list of packets and preserves egress packets categorized by NH mac address

            Returns:
            dictionary:NH mac addr : list of packets associated to NH on egress
        """
        dest_mac_pkt_distribution = {}  # holds [dest_mac : [pkts]]
        members = ecmp_group.get_members()
        for m in members:
            dest_mac_pkt_distribution[T.mac_addr.mac_num_to_str(m.downcast().get_mac().flat)] = []

        for packet in input_packets:
            egress_packets = U.run_and_get(self, self.device,
                                           packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)
            assert len(egress_packets) == 1
            egress_packet = egress_packets[0]
            scapy_egress_packet = U.hex_to_scapy(egress_packet.packet)
            dst_mac = scapy_egress_packet.dst

            # Find next hop
            found = False
            for m in members:
                if m.type() == sdk.la_object.object_type_e_NEXT_HOP:
                    nh = m.downcast()
                    if nh.get_mac().flat == T.mac_addr(dst_mac).to_num():
                        found = True
                        break
            assert found is not False, 'No next hop in group with MAC addr %s' % dst_mac

            dest_mac_pkt_distribution[dst_mac] = dest_mac_pkt_distribution.get(
                dst_mac, []) + [packet]  # Append each packet associated with dst_mac

        return dest_mac_pkt_distribution

    def create_input_packets(self, count=100):
        packets = []
        for i in range(count):
            input_packet = U.add_payload(self.INPUT_PACKET_BASE, self.PAYLOAD_SIZE)
            input_packet[TCP].sport = i
            input_packet[TCP].dport = i
            packets.append(input_packet)

        return packets

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_load_balancing_node_id(self):
        nh1 = self.topology.nh_l3_ac_def
        nh2 = self.topology.nh_l3_ac_reg

        ecmp_group = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        ecmp_group.add_member(nh1.hld_obj)
        ecmp_group.add_member(nh2.hld_obj)

        self.add_default_route(ecmp_group)

        old_lb_node_id = self.device.device.get_load_balancing_node_id()
        self.device.device.set_load_balancing_node_id(self.LOAD_BALANCING_ID)
        self.assertEqual(self.device.device.get_load_balancing_node_id(), self.LOAD_BALANCING_ID)

        input_packet = U.add_payload(self.INPUT_PACKET_BASE, self.PAYLOAD_SIZE)

        expected_packet, out_slice, out_ifg, out_pif = self.calculate_expected_output_ecmp(input_packet, ecmp_group)
        U.run_and_compare(self, self.device,
                          input_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          expected_packet, out_slice, out_ifg, out_pif)

        self.device.device.set_load_balancing_node_id(old_lb_node_id)

        self.destroy_default_route()

    @unittest.skipIf(decor.is_valgrind(), "Disabled due to performance concern")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_load_balancing_node_id_extended(self):
        """                                                                                                                     """
        """Eg. (these are arbitrary values, actual distribution may differ)                                                     """
        """100 flows (1 pkt per flow for simplicity)                                                                            """
        """                                                                                                                     """
        """Case 0:                                                                                                              """
        """        On route R1 - R2 - R4 - 50 packets                                                                           """
        """                 R1 - R2 - R5 - 0 packets                                                                            """
        """                 Both on R1 and R2 routers apply the same LB hash function                                           """
        """                 resulting in repeated load balance on R2.                                                           """
        """                                                                                                                     """
        """                                     -----3---- R4  - (50)                                                           """
        """                    (50) ---1--- R2  -----4---- R5  - (0)                                                            """
        """    100pkts -  R1                                                                                                    """
        """                    (50) ---2--- R3  ------5--- R4                                                                   """
        """                                     ------6--- R5                                                                   """
        """                                                                                                                     """
        """                                                                                                                     """
        """Case 1: In this case, we configure different lb_node_id on R2                                                        """
        """                On route R1 - R2 - R4 - 25 packets                                                                   """
        """                         R1 - R2 - R5 - 25 packets                                                                   """
        """                                                                                                                     """
        """                                     -----3---- R4  - (25)                                                           """
        """                    (50) ---1--- R2  -----4---- R5  - (25)                                                           """
        """    100pkts -  R1                                                                                                    """
        """                    (50) ---2--- R3  ------5--- R4                                                                   """
        """                                     ------6--- R5                                                                   """
        """                                                                                                                     """
        """Test:                                                                                                                """
        """        Using a single router:                                                                                       """
        """                                                                                                                     """
        """        - First:                                                                                                     """
        """                a) 100pkts --> R --> [50, 50]                                                                        """
        """                b) 50pkts  --> R --> [50, 0] - input packet from one of destinations from a)                         """
        """                                                                                                                     """
        """        - Second:                                                                                                    """
        """                a) 100pkts --> R --> [50, 50]                                                                        """
        """                b) 50pkts  --> R --> [25, 25] - input packet from one of destinations from a)                        """
        """                                                                                                                     """
        NUM_OF_NH = 2
        NUM_OF_PACKETS = 100

        NH_GID_BASE = 0x613
        NH_DST_MAC_BASE = T.mac_addr('11:11:11:11:11:00')
        EXT_MAC = T.mac_addr('be:be:be:be:be:be')
        TTL = 128
        SIP_local = T.ipv4_addr('155.24.162.37')
        DIP_BASE_local = T.ipv4_addr('111.111.111.111')

        l3_port_impl = T.ip_l3_ac_base(self.topology)

        ecmp_group = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        for nh_num in range(NUM_OF_NH):
            nh = T.next_hop(
                self,
                self.device,
                NH_GID_BASE + nh_num,
                NH_DST_MAC_BASE.create_offset_mac(nh_num),
                l3_port_impl.tx_port)
            ecmp_group.add_member(nh.hld_obj)

        self.add_default_route(ecmp_group)

        # Initial run
        input_packets_r0 = self.create_input_packets()
        output_distribution = self.do_run_and_get_distribution_ecmp(input_packets_r0, ecmp_group)

        # For Debug purpose:
        #self.print_distribution(output_distribution, "r0 output distribution :")

        # Take list of packets that egress a destination and re-run
        input_packets_r1 = None
        for v in output_distribution.values():
            if v:
                input_packets_r1 = v
        output_distribution = self.do_run_and_get_distribution_ecmp(input_packets_r1, ecmp_group)

        is_under_treshold = self.is_any_dst_under_treshold(input_packets_r1, output_distribution, NUM_OF_PACKETS)
        self.assertTrue(is_under_treshold)

        # For Debug purpose:
        #self.print_distribution(output_distribution, "r1 output distribution (node_id not set) : ")

        # Re-run once again but this time with non default LB ID
        old_lb_node_id = self.device.device.get_load_balancing_node_id()
        assert old_lb_node_id != self.LOAD_BALANCING_ID
        self.device.device.set_load_balancing_node_id(self.LOAD_BALANCING_ID)
        output_distribution = self.do_run_and_get_distribution_ecmp(input_packets_r1, ecmp_group)

        # For Debug purpose:
        #self.print_distribution(output_distribution, "r1 output distribution (node_id is set) :  ")

        is_under_treshold = self.is_any_dst_under_treshold(input_packets_r1, output_distribution, NUM_OF_PACKETS)
        self.assertFalse(is_under_treshold)

        self.destroy_default_route()


if __name__ == '__main__':
    unittest.main()
