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
from packet_test_utils import *
from scapy.all import *
from l2_counters_base import *
import unittest
from leaba import sdk
import sim_utils
import topology as T


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class add_and_forwarding(l2_counters_base):
    def setUp(self):
        super().setUp()
        # MATILDA_SAVE -- need review
        global IN_SLICE, OUT_SLICE, OUT_SLICE_2, OUT_SLICE_1
        if (IN_SLICE not in self.device.get_used_slices()):
            IN_SLICE = T.choose_active_slices(self.device, IN_SLICE, [1, 3])
        if (OUT_SLICE not in self.device.get_used_slices()):
            OUT_SLICE = T.choose_active_slices(self.device, OUT_SLICE, [4, 2])
        if (OUT_SLICE_1 not in self.device.get_used_slices()):
            OUT_SLICE_1 = T.choose_active_slices(self.device, OUT_SLICE_1, [5, 0])
        OUT_SLICE_2 = OUT_SLICE

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ac_port_creation_on_spa_delayed_system_port_add_and_forwarding(self):
        vid1 = VLAN
        vid2 = 0x0

        # Create RX ac port
        eth_port1 = T.ethernet_port(self, self.device, IN_SLICE, IN_IFG, SYS_PORT_GID_BASE, IN_SERDES_FIRST, IN_SERDES_LAST)
        eth_port1.set_ac_profile(self.ac_profile)
        ac_port1 = T.l2_ac_port(
            self,
            self.device,
            AC_PORT_GID_BASE,
            self.topology.filter_group_def,
            None,
            eth_port1,
            None,
            VLAN,
            0x0)

        # Create TX SPA
        spa_port = T.spa_port(self, self.device, SYS_PORT_GID_BASE + 1)

        # Create TX Ethernet port over the SPA
        eth_port2 = T.sa_ethernet_port(self, self.device, spa_port)
        eth_port1.set_ac_profile(self.ac_profile)

        # Create TX ac port over the SPA eth_port
        ac_port2 = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE + 1, self.topology.filter_group_def, None, eth_port2, None)

        # Create and set ingress counter
        counter_set_size = 1
        ingress_counter = self.device.create_counter(counter_set_size)
        ac_port1.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, ingress_counter)

        # Create and set egress counter
        egress_counter = self.device.create_counter(counter_set_size)
        ac_port2.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, egress_counter)

        # Create Switch
        sw1 = T.switch(self, self.device, SWITCH_GID)

        # Attach RX and TX ac ports to switch
        ac_port1.hld_obj.attach_to_switch(sw1.hld_obj)
        ac_port2.hld_obj.attach_to_switch(sw1.hld_obj)

        # Add 'cafecafecafe' to the MAC table, going to egress ac port
        dest_mac = T.mac_addr(DST_MAC)
        sw1.hld_obj.set_mac_entry(dest_mac.hld_obj, ac_port2.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)

        # Create egress system ports
        mac_port1 = T.mac_port(self, self.device, OUT_SLICE_1, OUT_IFG_1, OUT_SERDES_FIRST, OUT_SERDES_LAST)
        mac_port1.activate()
        mac_port2 = T.mac_port(self, self.device, OUT_SLICE_2, OUT_IFG_2, OUT_SERDES_FIRST, OUT_SERDES_LAST)
        mac_port2.activate()

        sys_port1 = T.system_port(self, self.device, SYS_PORT_GID_BASE + 2, mac_port1)
        sys_port2 = T.system_port(self, self.device, SYS_PORT_GID_BASE + 3, mac_port2)

        # add system ports to SPA
        spa_port.add(sys_port1)
        spa_port.add(sys_port2)

        # Inject packet_count
        prio = 0  # arbitray value
        in_packet_1, out_packet_1 = self.create_packets(prio, packet_to_use=1)
        in_packet_2, out_packet_2 = self.create_packets(prio, packet_to_use=2)

        self.run_and_compare_spa(spa_port, in_packet_2, IN_SLICE, IN_IFG, IN_SERDES_FIRST, out_packet_2)
        self.run_and_compare_spa(spa_port, in_packet_1, IN_SLICE, IN_IFG, IN_SERDES_FIRST, out_packet_1)

        # Check ingress counter
        packet_count, byte_count = ingress_counter.read(0,    # sub-counter index
                                                        True,  # force_update
                                                        True)  # clear_on_read
        self.assertEqual(packet_count, 2)
        assertPacketLengthIngress(self, in_packet_1, IN_SLICE, byte_count, num_packets=2)
        assertPacketLengthIngress(self, in_packet_2, IN_SLICE, byte_count, num_packets=2)

        # Check egress counter
        packet_count, byte_count = egress_counter.read(0,    # sub-counter index
                                                       True,  # force_update
                                                       True)  # clear_on_read
        self.assertEqual(packet_count, 2)
        assertPacketLengthEgress(self, out_packet_1, byte_count, num_packets=2)
        assertPacketLengthEgress(self, out_packet_2, byte_count, num_packets=2)

    def run_and_compare_spa(self, spa_port, input_packet, input_slice, input_ifg, input_serdes, out_packet):
        dst_mac = T.mac_addr(input_packet[Ether].dst)
        src_mac = T.mac_addr(input_packet[Ether].src)

        hw_lb_vec = sdk.la_lb_vector_t()
        hw_lb_vec.type = sdk.LA_LB_VECTOR_ETHERNET_VLAN_TAG
        hw_lb_vec.ethernet.vlan_id = VLAN
        hw_lb_vec.ethernet.da = dst_mac.hld_obj
        hw_lb_vec.ethernet.sa = src_mac.hld_obj

        dip = T.ipv4_addr(input_packet[IP].dst)
        sip = T.ipv4_addr(input_packet[IP].src)

        soft_lb_vec = sdk.la_lb_vector_t()
        if decor.is_akpg():
            soft_lb_vec.type = sdk.LA_LB_VECTOR_ETHER_VLAN_IPV4_L4
        else:
            soft_lb_vec.type = sdk.LA_LB_VECTOR_IPV4_NON_TCP_UDP
        soft_lb_vec.ipv4.sip = sip.hld_obj.s_addr
        soft_lb_vec.ipv4.dip = dip.hld_obj.s_addr
        soft_lb_vec.ipv4.protocol = input_packet[IP].proto

        lb_vec_entry_list = []
        lb_vec_entry_list.append(hw_lb_vec)
        lb_vec_entry_list.append(soft_lb_vec)

        out_dest_chain = self.device.get_forwarding_load_balance_chain(spa_port.hld_obj, lb_vec_entry_list)

        self.assertEqual(out_dest_chain[-1].type(), sdk.la_object.object_type_e_SYSTEM_PORT)

        out_dsp = out_dest_chain[-1].downcast()
        run_and_compare(self, self.device,
                        input_packet, input_slice, input_ifg, input_serdes,
                        out_packet, out_dsp.get_slice(), out_dsp.get_ifg(), out_dsp.get_base_serdes())


if __name__ == '__main__':
    unittest.main()
