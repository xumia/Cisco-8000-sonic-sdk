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

from scapy.config import conf
conf.ipv6_enabled = False
from scapy.all import *

from packet_test_utils import *
import unittest
from leaba import sdk
import sim_utils
import topology as T
from ipv4_mc import *
from sdk_multi_test_case_base import *
import mtu.mtu_test_utils as MTU
import ip_test_base


class ipv4_g_mc(sdk_multi_test_case_base):
    MC_GROUP_ADDR = T.ipv4_addr('225.1.2.3')
    MC_GROUP_ADDR_MISS = T.ipv4_addr('225.1.2.13')  # This group address will be used for (*,g) MISS testcases

    def setUp(self):

        self.device_name = '/dev/testdev'

        super().setUp()
        mc_base.BRIDGE_SLICE = T.choose_active_slices(self.device, mc_base.BRIDGE_SLICE, [4, 2])

        self.l3_port_impl = self.l3_port_impl_class(self.topology)

        self.topology.rx_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)

        self.mc_group = self.device.create_ip_multicast_group(mc_base.MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)
        self.mc_group.add(self.l3_port_impl.tx_port.hld_obj, self.get_tx_l2_port(), self.get_tx_sys_port())
        self.mc_group.add(self.l3_port_impl.tx_port_def.hld_obj, self.get_tx_l2_port_def(), self.get_tx_sys_port_def())
        self.empty_mc_group = self.device.create_ip_multicast_group(
            mc_base.MC_EMPTY_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)

        self.port_counters = [self.device.create_counter(5) for i in range(2)]
        self.l3_port_impl.tx_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.port_counters[0])
        self.l3_port_impl.tx_port_def.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.port_counters[1])

        self.counter = self.device.create_counter(1)  # set_size=1
        self.rpf_intf = None
        self.trap = False
        self.is_mcast_route_hit = True
        self.rpffail = False

    def setup_for_ingress_rep(self):
        self.ingress_group = self.device.create_ip_multicast_group(mc_base.MC_GROUP_GID + 2, sdk.la_replication_paradigm_e_INGRESS)
        if (self.svi):
            self.txsvi_mcg = self.device.create_l2_multicast_group(mc_base.MC_GROUP_GID + 3, sdk.la_replication_paradigm_e_EGRESS)
            self.txsvi_mcg.add(self.get_tx_l2_port(), self.get_tx_sys_port())
            self.txsvi_mcg.add(self.get_tx_l2_port_def(), self.get_tx_sys_port_def())
            self.ingress_group.add(self.l3_port_impl.tx_port.hld_obj, self.txsvi_mcg)

            self.rxsvi_mcg = self.device.create_l2_multicast_group(mc_base.MC_GROUP_GID + 4, sdk.la_replication_paradigm_e_EGRESS)
            self.rxsvi_mcg.add(self.ac_port1.hld_obj, self.eth_port1.sys_port.hld_obj)
            self.rxsvi_mcg.add(self.ac_port2.hld_obj, self.eth_port2.sys_port.hld_obj)
            if (not self.rpffail):
                self.ingress_group.add(self.l3_port_impl.rx_port.hld_obj, self.rxsvi_mcg)
        else:
            self.ingress_group.add(self.mc_group)

    def do_test_route(self, extra_packet=None, punt_and_forward=False, disable_rx=False, disable_tx=False):
        # test egress replication
        self.do_test_mc_route(self.mc_group, extra_packet, punt_and_forward, disable_rx, disable_tx)

    def do_test_route_ir(self, extra_packet=None, punt_and_forward=False):
        # test ingress replication
        self.setup_for_ingress_rep()
        self.do_test_mc_route(self.ingress_group, extra_packet, punt_and_forward, disable_rx=False, disable_tx=False)

    def do_test_mc_route(self, mc_group, extra_packet, punt_and_forward, disable_rx, disable_tx):

        self.topology.vrf.hld_obj.add_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP, ipv4_g_mc.MC_GROUP_ADDR.hld_obj, mc_group, self.rpf_intf, False, punt_and_forward, None)

        if(self.svi):
            self.topology.rx_switch.hld_obj.add_ipv4_multicast_route(ipv4_g_mc.MC_GROUP_ADDR.hld_obj, self.rxsw_snoop)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}

        expected_packets = []
        expected_packets_disable = []
        # receive forward copies
        if (not self.trap):
            expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                     'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
            expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DEF, 'slice': T.TX_SLICE_DEF,
                                     'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
            # We will disable the tx_port_reg, so packet on tx_port_def will still be received
            expected_packets_disable.append({'data': self.EXPECTED_OUTPUT_PACKET_DEF, 'slice': T.TX_SLICE_DEF,
                                             'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})

        # receive cpu copy
        if extra_packet is not None:
            expected_packets.append({'data': extra_packet.packet, 'slice': extra_packet.slice_id,
                                     'ifg': extra_packet.ifg, 'pif': extra_packet.serdes})
            expected_packets_disable.append({'data': extra_packet.packet, 'slice': extra_packet.slice_id,
                                             'ifg': extra_packet.ifg, 'pif': extra_packet.serdes})
        # receive bridge copies
        if (self.svi):
            expected_packets.append({'data': self.INPUT_PACKET, 'slice': mc_base.BRIDGE_SLICE,
                                     'ifg': mc_base.BRIDGE_IFG, 'pif': mc_base.BRIDGE_SERDES1})
            expected_packets.append({'data': self.INPUT_PACKET, 'slice': mc_base.BRIDGE_SLICE,
                                     'ifg': mc_base.BRIDGE_IFG, 'pif': mc_base.BRIDGE_SERDES2})

        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        self.topology.vrf.hld_obj.modify_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP,
            ipv4_g_mc.MC_GROUP_ADDR.hld_obj,
            mc_group,
            self.rpf_intf,
            False,
            punt_and_forward,
            self.counter)

        for c in self.port_counters:
            c.read(sdk.la_l3_protocol_e_IPV4_MC, True, True)  # clear port MC counters

        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

#        packet_count, byte_count = self.counter.read(0,  # sub-counter index
#                                                     True,  # force_update
#                                                     True)  # clear_on_read

        port_counts_mc = [c.read(sdk.la_l3_protocol_e_IPV4_MC, True, True) for c in self.port_counters]

#        if (self.is_mcast_route_hit):
#            self.assertEqual(packet_count, 1)
#            assertPacketLengthIngress(self, self.INPUT_PACKET, T.RX_SLICE, byte_count)

        if not self.trap and not self.svi:
            for packet_count, byte_count in port_counts_mc:
                self.assertEqual(packet_count, 1)
                assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET, byte_count)

        if(not self.l3_port_impl.is_svi):
            if(disable_rx):
                self.l3_port_impl.rx_port.hld_obj.disable()
                U.run_and_drop(self, self.device,
                               self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

            if(disable_tx):
                self.l3_port_impl.tx_port.hld_obj.disable()
                run_and_compare_list(self, self.device, ingress_packet, expected_packets_disable, Ether)

        # Cleanup
        self.topology.vrf.hld_obj.delete_ipv4_multicast_route(sdk.LA_IPV4_ANY_IP, ipv4_g_mc.MC_GROUP_ADDR.hld_obj)
        if (self.svi):
            self.topology.rx_switch.hld_obj.delete_ipv4_multicast_route(ipv4_g_mc.MC_GROUP_ADDR.hld_obj)

    def do_test_route_to_empty_mcg(self, extra_packet=None, punt_and_forward=False, punt_on_rpf_fail=False):
        self.topology.vrf.hld_obj.add_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP,
            ipv4_g_mc.MC_GROUP_ADDR.hld_obj,
            self.empty_mc_group,
            self.rpf_intf,
            punt_on_rpf_fail,
            punt_and_forward,
            None)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []

        # receive snoop copy
        if extra_packet is not None:
            expected_packets.append({'data': extra_packet.packet, 'slice': extra_packet.slice_id,
                                     'ifg': extra_packet.ifg, 'pif': extra_packet.serdes})

        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.topology.vrf.hld_obj.modify_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP,
            ipv4_g_mc.MC_GROUP_ADDR.hld_obj,
            self.empty_mc_group,
            self.rpf_intf,
            punt_on_rpf_fail,
            punt_and_forward,
            self.counter)

        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

#        packet_count, byte_count = self.counter.read(0,  # sub-counter index
#                                                     True,  # force_update
#                                                     True)  # clear_on_read
#
#        if (self.is_mcast_route_hit):
#            self.assertEqual(packet_count, 1)
#            assertPacketLengthIngress(self, self.INPUT_PACKET, T.RX_SLICE, byte_count)

        # Cleanup
        self.topology.vrf.hld_obj.delete_ipv4_multicast_route(sdk.LA_IPV4_ANY_IP, ipv4_g_mc.MC_GROUP_ADDR.hld_obj)

    def do_test_route_mtu(self, extra_packet=None, punt_and_forward=False):

        self.topology.vrf.hld_obj.add_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP, ipv4_g_mc.MC_GROUP_ADDR.hld_obj, self.mc_group, None, False, punt_and_forward, None)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        if extra_packet is not None:
            expected_packets.append({'data': extra_packet.packet, 'slice': extra_packet.slice_id,
                                     'ifg': extra_packet.ifg, 'pif': extra_packet.serdes, 'ingress_mirror_pi_port_pkt': True})
        MTU.run_mtu_tests(self, self.device, ingress_packet, expected_packets, Ether)

        # Cleanup
        self.topology.vrf.hld_obj.delete_ipv4_multicast_route(sdk.LA_IPV4_ANY_IP, ipv4_g_mc.MC_GROUP_ADDR.hld_obj)
