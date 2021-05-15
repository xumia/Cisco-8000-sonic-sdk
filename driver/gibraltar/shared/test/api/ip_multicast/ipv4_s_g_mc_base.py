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


class ipv4_s_g_mc(sdk_multi_test_case_base):
    MC_GROUP_ADDR = T.ipv4_addr('232.1.2.3')

    def setUp(self):

        super().setUp()
        mc_base.rechoose_odd_inject_slice(self.device)

        self.l3_port_impl = self.l3_port_impl_class(self.topology)

        self.topology.rx_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)

        self.mc_group = self.device.create_ip_multicast_group(mc_base.MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)
        self.mc_group.add(self.l3_port_impl.tx_port.hld_obj, self.get_tx_l2_port(), self.get_tx_sys_port())
        self.mc_group.add(self.l3_port_impl.tx_port_def.hld_obj, self.get_tx_l2_port_def(), self.get_tx_sys_port_def())

        self.counter = self.device.create_counter(1)  # set_size=1
        self.ingress_l2_counter_set_size = sdk.la_rate_limiters_packet_type_e_LAST
        self.ingress_l2_counter = self.device.create_counter(self.ingress_l2_counter_set_size)

        self.pi_port = T.punt_inject_port(self, self.device, mc_base.INJECT_SLICE, mc_base.INJECT_IFG, mc_base.INJECT_SP_GID,
                                          mc_base.INJECT_PIF_FIRST, mc_base.PUNT_INJECT_PORT_MAC_ADDR)
        self.punt_dest = T.create_l2_punt_destination(self, self.device, T.L2_PUNT_DESTINATION2_GID,
                                                      self.pi_port, mc_base.HOST_MAC_ADDR, mc_base.PUNT_VLAN)
        self.mirror_cmd = T.create_l2_mirror_command(
            self.device,
            mc_base.MIRROR_CMD_INGRESS_GID,
            self.pi_port,
            mc_base.HOST_MAC_ADDR,
            mc_base.MIRROR_VLAN)

        mc_base.initSnoopsAndTraps(self.device, self.punt_dest, self.mirror_cmd)
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

    def do_test_route(self, extra_packet=None, punt_and_forward=False,
                      punt_on_rpf_fail=False, disable_rx=False, disable_tx=False):
        # Test egress replication
        self.do_test_mc_route(self.mc_group, extra_packet, punt_and_forward, punt_on_rpf_fail, disable_rx, disable_tx)

    def do_test_route_ir(self, extra_packet=None, punt_and_forward=False, punt_on_rpf_fail=False):
        # Test ingress replication
        self.setup_for_ingress_rep()
        self.do_test_mc_route(
            self.ingress_group,
            extra_packet,
            punt_and_forward,
            punt_on_rpf_fail,
            disable_rx=False,
            disable_tx=False)

    def do_test_mc_route(self, mc_group, extra_packet, punt_and_forward, punt_on_rpf_fail, disable_rx, disable_tx):

        self.topology.vrf.hld_obj.add_ipv4_multicast_route(
            ipv4_mc.SIP.hld_obj,
            ipv4_s_g_mc.MC_GROUP_ADDR.hld_obj,
            mc_group,
            self.rpf_intf,
            punt_on_rpf_fail,
            punt_and_forward,
            None)
        if(self.svi):
            self.topology.rx_switch.hld_obj.add_ipv4_multicast_route(ipv4_s_g_mc.MC_GROUP_ADDR.hld_obj, self.rxsw_snoop)

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
        # receive bridge copies
        if (self.svi):
            expected_packets.append({'data': self.INPUT_PACKET, 'slice': mc_base.BRIDGE_SLICE,
                                     'ifg': mc_base.BRIDGE_IFG, 'pif': mc_base.BRIDGE_SERDES1})
            expected_packets.append({'data': self.INPUT_PACKET, 'slice': mc_base.BRIDGE_SLICE,
                                     'ifg': mc_base.BRIDGE_IFG, 'pif': mc_base.BRIDGE_SERDES2})

        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        # enable RPF and verify that mcast still works
        self.l3_port_impl.rx_port.hld_obj.set_urpf_mode(sdk.la_l3_port.urpf_mode_e_LOOSE)
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.topology.vrf.hld_obj.modify_ipv4_multicast_route(
            ipv4_mc.SIP.hld_obj,
            ipv4_s_g_mc.MC_GROUP_ADDR.hld_obj,
            mc_group,
            self.rpf_intf,
            punt_on_rpf_fail,
            punt_and_forward,
            self.counter)

        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        if(not self.l3_port_impl.is_svi):
            if(disable_rx):
                self.topology.rx_l3_ac.hld_obj.disable()
                U.run_and_drop(self, self.device,
                               self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

            if(disable_tx):
                self.l3_port_impl.tx_port.hld_obj.disable()
                run_and_compare_list(self, self.device, ingress_packet, expected_packets_disable, Ether)

#        packet_count, byte_count = self.counter.read(0,  # sub-counter index
#                                                     True,  # force_update
#                                                     True)  # clear_on_read
#        if (self.is_mcast_route_hit):
#            self.assertEqual(packet_count, 1)
#            assertPacketLengthIngress(self, self.INPUT_PACKET, T.RX_SLICE, byte_count)

        # Cleanup
        self.topology.vrf.hld_obj.delete_ipv4_multicast_route(ipv4_mc.SIP.hld_obj, ipv4_s_g_mc.MC_GROUP_ADDR.hld_obj)
        if (self.svi):
            self.topology.rx_switch.hld_obj.delete_ipv4_multicast_route(ipv4_s_g_mc.MC_GROUP_ADDR.hld_obj)

    def do_test_route_pkt_count(self, punt_and_forward=False):
        self.topology.vrf.hld_obj.add_ipv4_multicast_route(
            ipv4_mc.SIP.hld_obj, ipv4_s_g_mc.MC_GROUP_ADDR.hld_obj, self.mc_group, None, False, punt_and_forward, None)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        self.topology.rx_l2_ac_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.ingress_l2_counter)
        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)
        packets, byte_count = self.ingress_l2_counter.read(sdk.la_rate_limiters_packet_type_e_MC, True, True)
        self.assertEqual(packets, 1)
        assertPacketLengthIngress(self, self.INPUT_PACKET, T.RX_SLICE, byte_count)

        # Cleanup

        self.topology.vrf.hld_obj.delete_ipv4_multicast_route(ipv4_mc.SIP.hld_obj, ipv4_s_g_mc.MC_GROUP_ADDR.hld_obj)
