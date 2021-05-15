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
import unittest
from leaba import sdk
import decor
import topology as T
from ipv4_mc import *
from ipv6_mc import *
from sdk_multi_test_case_base import *

from scapy.config import conf
conf.ipv6_enabled = False
from scapy.all import *

from ipv4_s_g_mc_base import *
from ipv4_g_mc_base import *
from egress_member_punt_base import *
from unmatched_mc_base import *

from ipv6_g_mc_base import *
from ipv6_s_g_mc_base import *
from ingress_replication_base import *


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class egress_member_punt_change_dsp(sdk_multi_test_case_base):
    MC_GROUP_ADDR = T.ipv4_addr('225.1.2.3')

    PORT_SLICES = [T.get_device_slice(1), T.get_device_slice(2)]
    PORT_IFGS = [T.get_device_ifg(1), T.get_device_ifg(1)]
    PORT_FIRST_SERDES = [T.get_device_out_first_serdes(4), T.get_device_out_next_first_serdes(6)]

    NUM_SYS_PORTS = 2
    SYS_PORT_GIDS = [12, 13]
    SPA_PORT_GID = 0
    L3_AC_GID = 0
    NH_L3_AC_GID = 1

    L3_AC_MAC = T.mac_addr('72:74:76:78:80:82')
    NH_L3_AC_MAC = T.mac_addr('11:22:33:44:55:66')

    PUNT_SLICE = T.get_device_slice(2)
    PUNT_IFG = 0
    PUNT_SERDES = T.get_device_next2_first_serdes(8)
    PUNT_SYS_PORT_GID = T.MIN_SYSTEM_PORT_GID
    PI_PORT_MAC = T.mac_addr('ab:ab:ab:ab:ab:ab')
    HOST_MAC_ADDR = T.mac_addr('cd:cd:cd:cd:cd:cd')
    PUNT_DEST_GID = 0x13
    PUNT_DEST_VID = 0x13
    PUNT_VLAN = 19

    INPUT_PACKET_BASE = Ether(dst=ipv4_mc.get_mc_sa_addr_str(MC_GROUP_ADDR),
                              src=egress_member_punt_base.SA.addr_str,
                              type=Ethertype.QinQ.value) / Dot1Q(vlan=T.RX_L3_AC_PORT_VID1,
                                                                 type=Ethertype.Dot1Q.value) / Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / IP(src=ipv4_mc.SIP.addr_str,
                                                                                                                                     dst=MC_GROUP_ADDR.addr_str,
                                                                                                                                     ttl=egress_member_punt_base.TTL) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_BASE = Ether(dst=ipv4_mc.get_mc_sa_addr_str(MC_GROUP_ADDR),
                                        src=L3_AC_MAC.addr_str) / IP(src=ipv4_mc.SIP.addr_str,
                                                                     dst=MC_GROUP_ADDR.addr_str,
                                                                     ttl=egress_member_punt_base.TTL - 1) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_PUNT_DSP_1_BASE = \
        Ether(dst=HOST_MAC_ADDR.addr_str, src=PI_PORT_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1Q(prio=0, id=0, vlan=PUNT_DEST_VID, type=Ethertype.Punt.value) / \
        Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_IPV4, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
             next_header_offset=0,
             source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_EGRESS_TRAP,
             code=sdk.LA_EVENT_L3_IP_MC_EGRESS_PUNT,
             source_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
             destination_sp=SYS_PORT_GIDS[0],
             source_lp=T.RX_L3_AC_GID,
             destination_lp=L3_AC_GID,
             relay_id=T.VRF_GID, lpts_flow_type=0) / \
        IP(src=ipv4_mc.SIP.addr_str, dst=MC_GROUP_ADDR.addr_str, ttl=egress_member_punt_base.TTL) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_PUNT_DSP_2_BASE = \
        Ether(dst=HOST_MAC_ADDR.addr_str, src=PI_PORT_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1Q(prio=0, id=0, vlan=PUNT_DEST_VID, type=Ethertype.Punt.value) / \
        Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_IPV4, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
             next_header_offset=0,
             source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_EGRESS_TRAP,
             code=sdk.LA_EVENT_L3_IP_MC_EGRESS_PUNT,
             source_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
             destination_sp=SYS_PORT_GIDS[1],
             source_lp=T.RX_L3_AC_GID,
             destination_lp=L3_AC_GID,
             relay_id=T.VRF_GID, lpts_flow_type=0) / \
        IP(src=ipv4_mc.SIP.addr_str, dst=MC_GROUP_ADDR.addr_str, ttl=egress_member_punt_base.TTL) / TCP() / Raw(load=RAW_PAYLOAD)

    INPUT_PACKET, EXPECTED_OUTPUT_PACKET = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)
    __, EXPECTED_OUTPUT_PACKET_PUNT_DSP_1 = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_PUNT_DSP_1_BASE)
    __, EXPECTED_OUTPUT_PACKET_PUNT_DSP_2 = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_PUNT_DSP_2_BASE)

    def setUp(self):
        super().setUp()
        self.pi_port = T.punt_inject_port(
            self,
            self.device,
            self.PUNT_SLICE,
            self.PUNT_IFG,
            self.PUNT_SYS_PORT_GID,
            self.PUNT_SERDES,
            self.PI_PORT_MAC.addr_str)

        self.punt_dest = T.create_l2_punt_destination(
            self,
            self.device,
            T.L2_PUNT_DESTINATION2_GID,
            self.pi_port,
            self.HOST_MAC_ADDR.addr_str,
            self.PUNT_VLAN)

        self.device.clear_trap_configuration(sdk.LA_EVENT_L3_IP_MC_EGRESS_PUNT)
        self.device.set_trap_configuration(sdk.LA_EVENT_L3_IP_MC_EGRESS_PUNT, 0, None, self.punt_dest, False, False, True, 0)

        self.system_ports = []
        self.spa_port = T.spa_port(self, self.device, egress_member_punt_change_dsp.SPA_PORT_GID)
        for x in range(egress_member_punt_change_dsp.NUM_SYS_PORTS):
            mac_port = T.mac_port(
                self,
                self.device,
                egress_member_punt_change_dsp.PORT_SLICES[x],
                egress_member_punt_change_dsp.PORT_IFGS[x],
                egress_member_punt_change_dsp.PORT_FIRST_SERDES[x],
                egress_member_punt_change_dsp.PORT_FIRST_SERDES[x] + 1)
            mac_port.activate()
            self.system_ports.append(T.system_port(self, self.device, egress_member_punt_change_dsp.SYS_PORT_GIDS[x], mac_port))
            self.spa_port.add(self.system_ports[x])

        self.eth_port = T.sa_ethernet_port(self, self.device, self.spa_port)
        self.l3_ac_port = T.l3_ac_port(
            self,
            self.device,
            egress_member_punt_change_dsp.L3_AC_GID,
            self.eth_port,
            self.topology.vrf,
            egress_member_punt_change_dsp.L3_AC_MAC)

        self.topology.rx_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)

    def create_mc_group(self, rep_paradigm):
        self.mc_group = self.device.create_ip_multicast_group(
            egress_member_punt_base.MC_GROUP_GID, rep_paradigm)
        self.mc_group.add(self.l3_ac_port.hld_obj, None, self.system_ports[0].hld_obj)

    def do_test_egress_member_punt_change_dsp(self):
        self.topology.vrf.hld_obj.add_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP, egress_member_punt_change_dsp.MC_GROUP_ADDR.hld_obj, self.mc_group, None, False, False, None)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}

        expected_packets = []
        expected_packets_switch = []

        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET,
                                 'slice': egress_member_punt_change_dsp.PORT_SLICES[0],
                                 'ifg': egress_member_punt_change_dsp.PORT_IFGS[0],
                                 'pif': egress_member_punt_change_dsp.PORT_FIRST_SERDES[0]})
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_PUNT_DSP_1,
                                 'slice': self.PUNT_SLICE, 'ifg': self.PUNT_IFG, 'pif': self.PUNT_SERDES})

        expected_packets_switch.append({'data': self.EXPECTED_OUTPUT_PACKET,
                                        'slice': egress_member_punt_change_dsp.PORT_SLICES[1],
                                        'ifg': egress_member_punt_change_dsp.PORT_IFGS[1],
                                        'pif': egress_member_punt_change_dsp.PORT_FIRST_SERDES[1]})
        expected_packets_switch.append({'data': self.EXPECTED_OUTPUT_PACKET_PUNT_DSP_2,
                                        'slice': self.PUNT_SLICE, 'ifg': self.PUNT_IFG, 'pif': self.PUNT_SERDES})

        self.mc_group.set_punt_enabled(self.l3_ac_port.hld_obj, None, True)

        run_and_compare_list(self, self.device, ingress_packet, expected_packets, Ether)

        self.mc_group.set_destination_system_port(self.l3_ac_port.hld_obj, None, self.system_ports[1].hld_obj)

        run_and_compare_list(self, self.device, ingress_packet, expected_packets_switch, Ether)

        # Cleanup
        self.topology.vrf.hld_obj.delete_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP, egress_member_punt_change_dsp.MC_GROUP_ADDR.hld_obj)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_member_punt_change_dsp(self):
        self.create_mc_group(sdk.la_replication_paradigm_e_EGRESS)
        self.do_test_egress_member_punt_change_dsp()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR  fails")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
    def test_egress_member_punt_change_dsp_ingress_rep(self):
        self.create_mc_group(sdk.la_replication_paradigm_e_INGRESS)
        self.do_test_egress_member_punt_change_dsp()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class add_remove_test(sdk_multi_test_case_base):
    MC_GROUP_GID = 0x13

    def setUp(self):
        super().setUp(create_default_topology=False)
        VRF_GID = 0x100 if not decor.is_gibraltar() else 0xF00
        vrf = T.vrf(self, self.device, VRF_GID)
        self.mc_group = self.device.create_ip_multicast_group(add_remove_test.MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)

        # create more ports on the same slice as l3_ac_reg
        for i in range(3):
            ep = T.ethernet_port(
                self,
                self.device,
                T.TX_SLICE_REG,
                T.TX_IFG_REG,
                T.TX_L3_AC_SYS_PORT_REG_GID + i,
                T.FIRST_SERDES_L3 + i * 2,
                T.LAST_SERDES_L3 + i * 2)

            acp = T.l3_ac_port(
                self,
                self.device,
                T.TX_L3_AC_REG_GID + i * 2,
                ep,
                vrf,
                T.TX_L3_AC_REG_MAC)

            self.mc_group.add(acp.hld_obj, None, ep.hld_obj.get_system_port())

    def test_remove(self):
        while self.mc_group.get_size() > 0:
            (mc_group_meminfo) = self.mc_group.get_member(0)
            self.mc_group.remove(mc_group_meminfo.l3_port, mc_group_meminfo.l2_port)


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class collapsed_mc_test(sdk_multi_test_case_base):
    MC_GROUP_ADDR = T.ipv4_addr('225.1.2.3')
    RX_SVI_GID = 0x2a
    RX_L2_AC_GID = 0x255
    RX_L2_AC_VID1 = 0xf
    RX_L2_AC_MAC = T.mac_addr('36:35:34:33:32:31')

    INPUT_PACKET_BASE = \
        Ether(dst=ipv4_mc.get_mc_sa_addr_str(MC_GROUP_ADDR), src=mc_base.SA.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
        IP(src=ipv4_mc.SIP.addr_str, dst=MC_GROUP_ADDR.addr_str, ttl=mc_base.TTL) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_BASE = \
        Ether(dst=ipv4_mc.get_mc_sa_addr_str(MC_GROUP_ADDR), src=T.TX_SVI_MAC.addr_str) / \
        IP(src=ipv4_mc.SIP.addr_str, dst=MC_GROUP_ADDR.addr_str, ttl=mc_base.TTL - 1) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_COLLAPSED_BASE = \
        Ether(dst=ipv4_mc.get_mc_sa_addr_str(MC_GROUP_ADDR), src=mc_base.SA.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
        IP(src=ipv4_mc.SIP.addr_str, dst=MC_GROUP_ADDR.addr_str, ttl=mc_base.TTL) / TCP() / Raw(load=RAW_PAYLOAD)

    INPUT_PACKET, EXPECTED_OUTPUT_PACKET = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)
    __, EXPECTED_OUTPUT_PACKET_COLLAPSED = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_COLLAPSED_BASE)

    output_serdes = T.FIRST_SERDES_SVI

    def setUp(self):

        super().setUp()

        self.topology.rx_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)

        self.mc_group = self.device.create_ip_multicast_group(mc_base.MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)
        self.mc_group.add(
            self.topology.tx_svi.hld_obj,
            self.topology.tx_l2_ac_port_reg.hld_obj,
            self.topology.tx_svi_eth_port_reg.sys_port.hld_obj)
        self.mc_group.add(
            self.topology.tx_svi.hld_obj,
            self.topology.tx_l2_ac_port_def.hld_obj,
            self.topology.tx_svi_eth_port_def.sys_port.hld_obj)

        self.counter = self.device.create_counter(1)  # set_size=1

        self.topology.rx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)

        self.rx_l2_ac = T.l2_ac_port(self, self.device, collapsed_mc_test.RX_L2_AC_GID, None, self.topology.rx_switch,
                                     self.topology.rx_eth_port, collapsed_mc_test.RX_L2_AC_MAC, collapsed_mc_test.RX_L2_AC_VID1)

        self.mc_group.add(self.topology.rx_svi.hld_obj, self.rx_l2_ac.hld_obj, self.topology.rx_eth_port.sys_port.hld_obj)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    def test_route(self):

        punt_and_forward = False
        self.topology.vrf.hld_obj.add_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP, collapsed_mc_test. MC_GROUP_ADDR.hld_obj, self.mc_group, None, False, punt_and_forward, None)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_COLLAPSED, 'slice': T.RX_SLICE,
                                 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        self.topology.vrf.hld_obj.modify_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP, collapsed_mc_test.MC_GROUP_ADDR.hld_obj, self.mc_group, None, False, punt_and_forward, self.counter)

        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

#        packet_count, byte_count = self.counter.read(0,  # sub-counter index
#                                                     True,  # force_update
#                                                     True)  # clear_on_read
#
#        self.assertEqual(packet_count, 1)
#        assertPacketLengthIngress(self, self.INPUT_PACKET, T.RX_SLICE, byte_count)

        self.topology.vrf.hld_obj.delete_ipv4_multicast_route(sdk.LA_IPV4_ANY_IP, collapsed_mc_test.MC_GROUP_ADDR.hld_obj)


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class get_ipv4_multicast_route_test(sdk_multi_test_case_base):
    MC_GROUP_ADDR = T.ipv4_addr('225.1.2.3')

    def setUp(self):
        super().setUp()

        self.topology.rx_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)

        self.mc_group = self.device.create_ip_multicast_group(mc_base.MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)
        self.mc_group.add(self.topology.tx_l3_ac_reg.hld_obj, None, self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj)
        self.mc_group.add(self.topology.tx_l3_ac_def.hld_obj, None, self.topology.tx_l3_ac_eth_port_def.sys_port.hld_obj)

        self.counter = self.device.create_counter(1)  # set_size=1

    def test_get(self):

        punt_and_forward = False
        punt_on_rpf_fail = False
        self.topology.vrf.hld_obj.add_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP,
            get_ipv4_multicast_route_test.MC_GROUP_ADDR.hld_obj,
            self.mc_group,
            None,
            punt_on_rpf_fail,
            punt_and_forward,
            self.counter)

        info = self.topology.vrf.hld_obj.get_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP, get_ipv4_multicast_route_test.MC_GROUP_ADDR.hld_obj)
        self.assertEqual(info.mcg.this, self.mc_group.this)
        self.assertEqual(info.counter.this, self.counter.this)
        self.assertFalse(info.punt_and_forward)
        self.assertFalse(info.punt_on_rpf_fail)
        self.assertIsNone(info.rpf)

        punt_and_forward = True
        punt_on_rpf_fail = True
        self.topology.vrf.hld_obj.modify_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP,
            get_ipv4_multicast_route_test.MC_GROUP_ADDR.hld_obj,
            self.mc_group,
            None,
            punt_on_rpf_fail,
            punt_and_forward,
            self.counter)

        info = self.topology.vrf.hld_obj.get_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP, get_ipv4_multicast_route_test.MC_GROUP_ADDR.hld_obj)
        self.assertEqual(info.mcg.this, self.mc_group.this)
        self.assertEqual(info.counter.this, self.counter.this)
        self.assertTrue(info.punt_and_forward)
        self.assertTrue(info.punt_on_rpf_fail)
        self.assertIsNone(info.rpf)

        self.topology.vrf.hld_obj.delete_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP, get_ipv4_multicast_route_test.MC_GROUP_ADDR.hld_obj)


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class get_ipv6_multicast_route_test(sdk_multi_test_case_base):
    MC_GROUP_ADDR = T.ipv6_addr('ff31:0:0:0:0:1:ffe8:658f')

    def setUp(self):

        super().setUp()

        self.topology.rx_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)

        self.mc_group = self.device.create_ip_multicast_group(mc_base.MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)
        self.mc_group.add(self.topology.tx_l3_ac_reg.hld_obj, None, self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj)
        self.mc_group.add(self.topology.tx_l3_ac_def.hld_obj, None, self.topology.tx_l3_ac_eth_port_def.sys_port.hld_obj)

        self.counter = self.device.create_counter(1)  # set_size=1

    def test_get(self):

        punt_and_forward = False
        self.topology.vrf.hld_obj.add_ipv6_multicast_route(
            sdk.LA_IPV6_ANY_IP,
            get_ipv6_multicast_route_test.MC_GROUP_ADDR.hld_obj,
            self.mc_group,
            self.topology.rx_l3_ac.hld_obj,
            False,
            punt_and_forward,
            self.counter)

        info = self.topology.vrf.hld_obj.get_ipv6_multicast_route(
            sdk.LA_IPV6_ANY_IP, get_ipv6_multicast_route_test.MC_GROUP_ADDR.hld_obj)
        self.assertEqual(info.mcg.this, self.mc_group.this)
        self.assertEqual(info.counter.this, self.counter.this)
        self.assertFalse(info.punt_and_forward)
        self.assertEqual(info.rpf.this, self.topology.rx_l3_ac.hld_obj.this)

        punt_and_forward = True
        self.topology.vrf.hld_obj.modify_ipv6_multicast_route(
            sdk.LA_IPV6_ANY_IP,
            get_ipv6_multicast_route_test.MC_GROUP_ADDR.hld_obj,
            self.mc_group,
            self.topology.rx_l3_ac.hld_obj,
            False,
            punt_and_forward,
            self.counter)

        info = self.topology.vrf.hld_obj.get_ipv6_multicast_route(
            sdk.LA_IPV6_ANY_IP, get_ipv6_multicast_route_test.MC_GROUP_ADDR.hld_obj)
        self.assertEqual(info.mcg.this, self.mc_group.this)
        self.assertEqual(info.counter.this, self.counter.this)
        self.assertTrue(info.punt_and_forward)
        self.assertEqual(info.rpf.this, self.topology.rx_l3_ac.hld_obj.this)

        self.topology.vrf.hld_obj.delete_ipv6_multicast_route(
            sdk.LA_IPV6_ANY_IP, get_ipv6_multicast_route_test.MC_GROUP_ADDR.hld_obj)


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class l2_same_interface_test(sdk_multi_test_case_base):
    MC_GROUP_ADDR = T.ipv4_addr('225.1.2.3')
    RX_SVI_GID = 0x2a
    RX_L2_AC_GID = 0x255
    RX_L2_AC_VID1 = 0xf
    RX_L2_AC_MAC = T.mac_addr('36:35:34:33:32:31')

    INPUT_PACKET_BASE = \
        Ether(dst=ipv4_mc.get_mc_sa_addr_str(MC_GROUP_ADDR), src=mc_base.SA.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
        IP(src=ipv4_mc.SIP.addr_str, dst=MC_GROUP_ADDR.addr_str, ttl=mc_base.TTL) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_BASE = \
        Ether(dst=ipv4_mc.get_mc_sa_addr_str(MC_GROUP_ADDR), src=T.TX_SVI_MAC.addr_str) / \
        IP(src=ipv4_mc.SIP.addr_str, dst=MC_GROUP_ADDR.addr_str, ttl=mc_base.TTL - 1) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_COLLAPSED_BASE = \
        Ether(dst=ipv4_mc.get_mc_sa_addr_str(MC_GROUP_ADDR), src=mc_base.SA.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
        IP(src=ipv4_mc.SIP.addr_str, dst=MC_GROUP_ADDR.addr_str, ttl=mc_base.TTL) / TCP() / Raw(load=RAW_PAYLOAD)

    INPUT_PACKET, EXPECTED_OUTPUT_PACKET = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)
    __, EXPECTED_OUTPUT_PACKET_COLLAPSED = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_COLLAPSED_BASE)
    output_serdes = T.FIRST_SERDES_SVI

    def setUp(self):
        super().setUp()

        self.topology.rx_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)

        self.mc_group = self.device.create_ip_multicast_group(mc_base.MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)
        self.mc_group.add(
            self.topology.tx_svi.hld_obj,
            self.topology.tx_l2_ac_port_reg.hld_obj,
            self.topology.tx_svi_eth_port_reg.sys_port.hld_obj)
        self.mc_group.add(
            self.topology.tx_svi.hld_obj,
            self.topology.tx_l2_ac_port_def.hld_obj,
            self.topology.tx_svi_eth_port_def.sys_port.hld_obj)

        self.counter = self.device.create_counter(1)  # set_size=1

        self.topology.rx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)

        self.rx_l2_ac = T.l2_ac_port(
            self,
            self.device,
            l2_same_interface_test.RX_L2_AC_GID,
            None,
            self.topology.rx_switch,
            self.topology.rx_eth_port,
            l2_same_interface_test.RX_L2_AC_MAC,
            l2_same_interface_test.RX_L2_AC_VID1)

        self.mc_group.add(self.topology.rx_svi.hld_obj, self.rx_l2_ac.hld_obj, self.topology.rx_eth_port.sys_port.hld_obj)

        # Same interface - should be dropped
        self.mc_group.add(
            self.topology.rx_svi.hld_obj,
            self.topology.rx_l2_ac_port.hld_obj,
            self.topology.rx_eth_port.sys_port.hld_obj)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route(self):

        punt_and_forward = False
        self.topology.vrf.hld_obj.add_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP, l2_same_interface_test.MC_GROUP_ADDR.hld_obj, self.mc_group, None, False, punt_and_forward, None)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_COLLAPSED, 'slice': T.RX_SLICE,
                                 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        self.topology.vrf.hld_obj.modify_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP,
            l2_same_interface_test.MC_GROUP_ADDR.hld_obj,
            self.mc_group,
            None,
            False,
            punt_and_forward,
            self.counter)

        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

#        packet_count, byte_count = self.counter.read(0,  # sub-counter index
#                                                     True,  # force_update
#                                                     True)  # clear_on_read
#
#        self.assertEqual(packet_count, 1)
#        assertPacketLengthIngress(self, self.INPUT_PACKET, T.RX_SLICE, byte_count)


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class l3_same_interface_test(sdk_multi_test_case_base):
    MC_GROUP_ADDR = T.ipv4_addr('225.1.2.3')
    RX_SVI_GID = 0x2a
    RX_L2_AC_GID = 0x255
    RX_L2_AC_VID1 = 0xf
    RX_L2_AC_VID1
    RX_L2_AC_MAC = T.mac_addr('36:35:34:33:32:31')

    INPUT_PACKET_BASE = \
        Ether(dst=ipv4_mc.get_mc_sa_addr_str(MC_GROUP_ADDR), src=mc_base.SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IP(src=ipv4_mc.SIP.addr_str, dst=MC_GROUP_ADDR.addr_str, ttl=mc_base.TTL) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_BASE = \
        Ether(dst=ipv4_mc.get_mc_sa_addr_str(MC_GROUP_ADDR), src=T.TX_L3_AC_REG_MAC.addr_str) / \
        IP(src=ipv4_mc.SIP.addr_str, dst=MC_GROUP_ADDR.addr_str, ttl=mc_base.TTL - 1) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_DEF_BASE = \
        Ether(dst=ipv4_mc.get_mc_sa_addr_str(MC_GROUP_ADDR), src=T.TX_L3_AC_DEF_MAC.addr_str) / \
        IP(src=ipv4_mc.SIP.addr_str, dst=MC_GROUP_ADDR.addr_str, ttl=mc_base.TTL - 1) / TCP() / Raw(load=RAW_PAYLOAD)

    INPUT_PACKET, EXPECTED_OUTPUT_PACKET = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)
    __, EXPECTED_OUTPUT_PACKET_DEF = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_DEF_BASE)

    def setUp(self):
        super().setUp()

        self.topology.rx_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)

        self.mc_group = self.device.create_ip_multicast_group(mc_base.MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)
        self.mc_group.add(self.topology.tx_l3_ac_reg.hld_obj, None, self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj)
        self.mc_group.add(self.topology.tx_l3_ac_def.hld_obj, None, self.topology.tx_l3_ac_eth_port_def.sys_port.hld_obj)

        self.counter = self.device.create_counter(1)  # set_size=1

        # Same interface - should be dropped
        self.mc_group.add(self.topology.rx_l3_ac.hld_obj, None, self.topology.rx_eth_port.sys_port.hld_obj)

        # Code for MC Group counter
        self.mcg_counter = self.device.create_counter(1)  # set_size=1

        self.device_id = self.device.get_id()
        self.mc_group.set_egress_counter(self.device_id, self.mcg_counter)
        #self.topology.rx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_gibraltar(), "Test is not yet enabled on GB")
    def test_route(self):
        punt_and_forward = False
        self.topology.vrf.hld_obj.add_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP, l3_same_interface_test.MC_GROUP_ADDR.hld_obj, self.mc_group, None, False, punt_and_forward, None)

        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': T.FIRST_SERDES_L3})
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DEF, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': T.FIRST_SERDES_L3})
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        # Read and verify MC group counter
        packet_count, byte_count = self.mcg_counter.read(0,  # sub-counter index
                                                         True,  # force_update
                                                         True)  # clear_on_read
        self.assertEqual(packet_count, 1)

        if (self.INPUT_PACKET[Ether].type == Ethertype.QinQ.value):  # MCG byte counter speculativly assumes no Dot1Q tag
            self.assertEqual(byte_count, len(self.INPUT_PACKET) - 8 + 4)  # Add Dual tag + CRC counted by Tx MCG counter
        elif (self.INPUT_PACKET[Ether].type == Ethertype.Dot1Q.value):
            self.assertEqual(byte_count, len(self.INPUT_PACKET) - 4 + 4)  # Add Tag + CRC counted by Tx MCG counter
        else:  # When input packt is untagged, the MCG byte counter is correct with just CRC adjustment
            self.assertEqual(byte_count, len(self.INPUT_PACKET) + 4)  # Add CRC counted by Tx MCG counter

        self.topology.vrf.hld_obj.modify_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP,
            l3_same_interface_test.MC_GROUP_ADDR.hld_obj,
            self.mc_group,
            None,
            False,
            punt_and_forward,
            self.counter)

        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

#        packet_count, byte_count = self.counter.read(0,  # sub-counter index
#                                                     True,  # force_update
#                                                     True)  # clear_on_read
#
#        self.assertEqual(packet_count, 1)
#        assertPacketLengthIngress(self, self.INPUT_PACKET, T.RX_SLICE, byte_count)


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv4_g_mc(sdk_multi_test_case_base):
    MC_GROUP_ADDR = T.ipv4_addr('225.1.2.3')

    def setUp(self):
        super().setUp()

        self.l3_port_impl_class = T.ip_l3_ac_base
        l3_port_impl = self.l3_port_impl_class(self.topology)

        self.topology.rx_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)

        mac_port1_first_serdes = T.get_device_next3_first_serdes(14)
        mac_port1_last_serdes = T.get_device_next3_last_serdes(15)
        mac_port2_first_serdes = T.get_device_next4_first_serdes(8)
        mac_port2_last_serdes = T.get_device_next4_first_serdes(9)
        mac_port1 = T.mac_port(self, self.device, 0, 0, mac_port1_first_serdes, mac_port1_last_serdes)
        mac_port2_slice = T.get_device_slice(1)
        mac_port2 = T.mac_port(self, self.device, mac_port2_slice, 0, mac_port2_first_serdes, mac_port2_last_serdes)

        sys_port1 = T.system_port(self, self.device, 0x10, mac_port1)
        sys_port2 = T.system_port(self, self.device, 0x20, mac_port2)

        mac_port1.activate()
        mac_port2.activate()

        spa_port = T.spa_port(self, self.device, 0x40)

        spa_port.add(sys_port1)

        eth_port = T.sa_ethernet_port(self, self.device, spa_port)
        mac_addr = T.mac_addr('71:72:73:74:25:76')
        self.l3_ac_port = T.l3_ac_port(self, self.device, 0x50, eth_port, self.topology.vrf, mac_addr)

        self.mc_group = self.device.create_ip_multicast_group(mc_base.MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)
        self.mc_group.add(self.l3_ac_port.hld_obj, None, sys_port1.hld_obj)

        spa_port.add(sys_port2)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route(self, extra_packet=None, punt_and_forward=False):
        self.mc_group.remove(self.l3_ac_port.hld_obj, None)


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class test_rpf(ipv6_s_g_mc):
    OUT_SLICE = T.get_device_slice(4)
    OUT_IFG = T.get_device_ifg(1)
    OUT_SERDES_FIRST = T.get_device_next_first_serdes(8)
    OUT_SERDES_LAST = OUT_SERDES_FIRST + 1

    OUT_SLICE1 = T.get_device_slice(1)
    OUT_IFG1 = 0
    OUT_SERDES_FIRST1 = T.get_device_out_first_serdes(12)
    OUT_SERDES_LAST1 = OUT_SERDES_FIRST1 + 1

    SYS_PORT_GID_BASE = 23
    AC_PORT_GID_BASE = 10
    L3_AC_MAC_ADDR = T.mac_addr('11:22:33:dd:ee:ff')

    INPUT_PACKET_BASE = \
        Ether(dst=ipv6_mc.get_mc_sa_addr_str(ipv6_s_g_mc.MC_GROUP_ADDR), src=mc_base.SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IPv6(src=ipv6_mc.SIP.addr_str, dst=ipv6_s_g_mc.MC_GROUP_ADDR.addr_str, hlim=mc_base.TTL, plen=40)

    EXPECTED_OUTPUT_PACKET_BASE = \
        Ether(dst=ipv6_mc.get_mc_sa_addr_str(ipv6_s_g_mc.MC_GROUP_ADDR), src=L3_AC_MAC_ADDR.addr_str) / \
        IPv6(src=ipv6_mc.SIP.addr_str, dst=ipv6_s_g_mc.MC_GROUP_ADDR.addr_str, hlim=mc_base.TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_DEF_BASE = \
        Ether(dst=ipv6_mc.get_mc_sa_addr_str(ipv6_s_g_mc.MC_GROUP_ADDR), src=T.TX_L3_AC_DEF_MAC.addr_str) / \
        IPv6(src=ipv6_mc.SIP.addr_str, dst=ipv6_s_g_mc.MC_GROUP_ADDR.addr_str, hlim=mc_base.TTL - 1, plen=40)

    INPUT_PACKET, EXPECTED_OUTPUT_PACKET = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)
    __, EXPECTED_OUTPUT_PACKET_DEF = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_DEF_BASE)

    l3_port_impl_class = T.ip_l3_ac_base
    output_serdes = T.FIRST_SERDES_L3

    def setUp(self):
        # MATILDA_SAVE -- need review
        if ip_set_dsp.OUT_SLICE not in self.device.get_used_slices():
            self.skipTest("In MATILDA model the tested slice has been deactivated, thus the test is shkiped.")
            return
        ipv6_s_g_mc.setUp(self)
        self.device.destroy(self.mc_group)  # we're going to use our own mc group

        # Create system-ports
        self.out_mac_port1 = T.mac_port(
            self,
            self.device,
            test_rpf.OUT_SLICE,
            test_rpf.OUT_IFG,
            test_rpf.OUT_SERDES_FIRST,
            test_rpf.OUT_SERDES_LAST)
        self.out_sys_port1 = T.system_port(self, self.device, test_rpf.SYS_PORT_GID_BASE + 1, self.out_mac_port1)

        self.out_mac_port1.activate()

        # Create SPA and add the system ports to it
        self.spa_port = T.spa_port(self, self.device, 123)
        self.spa_port.add(self.out_sys_port1)

        # Create high-level ports
        self.eth_port = T.sa_ethernet_port(self, self.device, self.spa_port)
        self.ac_port = T.l3_ac_port(
            self,
            self.device,
            test_rpf.AC_PORT_GID_BASE,
            self.eth_port,
            self.topology.vrf,
            test_rpf.L3_AC_MAC_ADDR)
        self.topology.rx_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)
        self.ac_port.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)

        # Create a MC group and add the L3 AC to it
        self.mc_group = self.device.create_ip_multicast_group(mc_base.MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)
        self.mc_group.add(self.ac_port.hld_obj, None, self.out_sys_port1.hld_obj)

        # Add the route with a wrong RPF
        # Correct RPF is checked in the test_ipv6_*_s_g tests
        punt_and_forward = False
        self.topology.vrf.hld_obj.add_ipv6_multicast_route(
            ipv6_mc.SIP.hld_obj,
            ipv6_s_g_mc.MC_GROUP_ADDR.hld_obj,
            self.mc_group,
            self.l3_port_impl.tx_port_def.hld_obj,
            False,
            punt_and_forward,
            None)

    def get_tx_l2_port(self):
        return None

    def get_tx_l2_port_def(self):
        return None

    def get_tx_sys_port(self):
        return self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj

    def get_tx_sys_port_def(self):
        return self.topology.tx_l3_ac_eth_port_def.sys_port.hld_obj

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_rpf(self):
        # Run the packet and check results
        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []  # RPF failure - no packets
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ip_set_dsp(ipv6_s_g_mc):
    OUT_SLICE = T.get_device_slice(4)
    OUT_IFG = T.get_device_ifg(1)
    OUT_SERDES_FIRST = T.get_device_next_first_serdes(8)
    OUT_SERDES_LAST = OUT_SERDES_FIRST + 1

    OUT_SLICE1 = T.get_device_slice(1)
    OUT_IFG1 = 0
    OUT_SERDES_FIRST1 = T.get_device_next2_first_serdes(12)
    OUT_SERDES_LAST1 = OUT_SERDES_FIRST1 + 1

    SYS_PORT_GID_BASE = 23
    AC_PORT_GID_BASE = 10
    L3_AC_MAC_ADDR = T.mac_addr('11:22:33:dd:ee:ff')

    MAC_PORT2_SLICE = 0

    INPUT_PACKET_BASE = \
        Ether(dst=ipv6_mc.get_mc_sa_addr_str(ipv6_s_g_mc.MC_GROUP_ADDR), src=mc_base.SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IPv6(src=ipv6_mc.SIP.addr_str, dst=ipv6_s_g_mc.MC_GROUP_ADDR.addr_str, hlim=mc_base.TTL, plen=40)

    EXPECTED_OUTPUT_PACKET_BASE = \
        Ether(dst=ipv6_mc.get_mc_sa_addr_str(ipv6_s_g_mc.MC_GROUP_ADDR), src=L3_AC_MAC_ADDR.addr_str) / \
        IPv6(src=ipv6_mc.SIP.addr_str, dst=ipv6_s_g_mc.MC_GROUP_ADDR.addr_str, hlim=mc_base.TTL - 1, plen=40)

    EXPECTED_OUTPUT_PACKET_DEF_BASE = \
        Ether(dst=ipv6_mc.get_mc_sa_addr_str(ipv6_s_g_mc.MC_GROUP_ADDR), src=T.TX_L3_AC_DEF_MAC.addr_str) / \
        IPv6(src=ipv6_mc.SIP.addr_str, dst=ipv6_s_g_mc.MC_GROUP_ADDR.addr_str, hlim=mc_base.TTL - 1, plen=40)

    INPUT_PACKET, EXPECTED_OUTPUT_PACKET = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)
    __, EXPECTED_OUTPUT_PACKET_DEF = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_DEF_BASE)

    l3_port_impl_class = T.ip_l3_ac_base
    output_serdes = T.FIRST_SERDES_L3

    def setUp(self):
        # MATILDA_SAVE -- need review
        if (ip_set_dsp.OUT_SLICE not in self.device.get_used_slices()) or (
                ip_set_dsp.OUT_SLICE1 not in self.device.get_used_slices()):
            self.skipTest("In MATILDA model the tested slice has been deactivated, thus the test is shkiped.")
            return
        ipv6_s_g_mc.setUp(self)
        self.device.destroy(self.mc_group)  # we're going to use our own mc group

    def get_tx_l2_port(self):
        return None

    def get_tx_l2_port_def(self):
        return None

    def get_tx_sys_port(self):
        return self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj

    def get_tx_sys_port_def(self):
        return self.topology.tx_l3_ac_eth_port_def.sys_port.hld_obj

    def do_test_set_dsp(self):

        # Run the packet and check results
        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': ip_set_dsp.OUT_SLICE,
                                 'ifg': ip_set_dsp.OUT_IFG, 'pif': ip_set_dsp.OUT_SERDES_FIRST})  # out_sys_port1
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

        # Change the dsp
        self.mc_group.set_destination_system_port(self.ac_port.hld_obj, None, self.out_sys_port2.hld_obj)

        # Re-run the packet and check results
        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': self.MAC_PORT2_SLICE,
                                 'ifg': ip_set_dsp.OUT_IFG1, 'pif': ip_set_dsp.OUT_SERDES_FIRST1})  # out_sys_port2
        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

    def init_parameters(self, rep_paradigm):

        # Create 2 output system-ports
        self.out_mac_port1 = T.mac_port(self, self.device, ip_set_dsp.OUT_SLICE, ip_set_dsp.OUT_IFG,
                                        ip_set_dsp.OUT_SERDES_FIRST, ip_set_dsp.OUT_SERDES_LAST)
        self.out_sys_port1 = T.system_port(self, self.device, ip_set_dsp.SYS_PORT_GID_BASE + 1, self.out_mac_port1)
        self.out_mac_port2 = T.mac_port(
            self,
            self.device,
            self.MAC_PORT2_SLICE,
            ip_set_dsp.OUT_IFG1,
            ip_set_dsp.OUT_SERDES_FIRST1,
            ip_set_dsp.OUT_SERDES_LAST1)
        self.out_sys_port2 = T.system_port(self, self.device, ip_set_dsp.SYS_PORT_GID_BASE + 2, self.out_mac_port2)

        self.out_mac_port1.activate()
        self.out_mac_port2.activate()

        # Create SPA and add the system ports to it
        self.spa_port = T.spa_port(self, self.device, 123)
        self.spa_port.add(self.out_sys_port1)
        self.spa_port.add(self.out_sys_port2)

        # Create high-level ports
        self.eth_port = T.sa_ethernet_port(self, self.device, self.spa_port)
        self.ac_port = T.l3_ac_port(
            self,
            self.device,
            ip_set_dsp.AC_PORT_GID_BASE,
            self.eth_port,
            self.topology.vrf,
            ip_set_dsp.L3_AC_MAC_ADDR)
        self.topology.rx_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)
        self.ac_port.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)

        # Create a MC group and add the L3 AC to it
        self.mc_group = self.device.create_ip_multicast_group(mc_base.MC_GROUP_GID, rep_paradigm)
        self.mc_group.add(self.ac_port.hld_obj, None, self.out_sys_port1.hld_obj)

        punt_and_forward = False
        self.topology.vrf.hld_obj.add_ipv6_multicast_route(
            ipv6_mc.SIP.hld_obj, ipv6_s_g_mc.MC_GROUP_ADDR.hld_obj, self.mc_group, None, False, punt_and_forward, None)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_getters(self):
        self.init_parameters(sdk.la_replication_paradigm_e_EGRESS)
        # DSP
        dsp = self.mc_group.get_destination_system_port(self.ac_port.hld_obj, None)
        self.assertEqual(dsp.this, self.out_sys_port1.hld_obj.this)

        # Size
        mcg_size = self.mc_group.get_size()
        self.assertEqual(mcg_size, 1)

        # Members
        (mc_group_meminfo) = self.mc_group.get_member(0)
        self.assertEqual(mc_group_meminfo.l3_port.this, self.ac_port.hld_obj.this)
        self.assertIsNone(mc_group_meminfo.l2_port)
        self.assertIsNone(mc_group_meminfo.l2_mcg)
        self.assertIsNone(mc_group_meminfo.ip_mcg)

        # Replication paradigm
        res_replication_paradigm = self.mc_group.get_replication_paradigm()
        self.assertEqual(res_replication_paradigm, sdk.la_replication_paradigm_e_EGRESS)

        mc_group2 = self.device.get_ip_multicast_group(mc_base.MC_GROUP_GID)
        self.assertEqual(mc_group2.this, self.mc_group.this)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ip_set_dsp_different_slice(self):
        self.MAC_PORT2_SLICE = ip_set_dsp.OUT_SLICE1
        self.init_parameters(sdk.la_replication_paradigm_e_EGRESS)
        self.do_test_set_dsp()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ip_set_dsp_same_slice(self):
        self.MAC_PORT2_SLICE = ip_set_dsp.OUT_SLICE
        self.init_parameters(sdk.la_replication_paradigm_e_EGRESS)
        self.do_test_set_dsp()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
    def test_ip_set_dsp_different_slice_ingress_rep(self):
        self.MAC_PORT2_SLICE = ip_set_dsp.OUT_SLICE1
        self.init_parameters(sdk.la_replication_paradigm_e_INGRESS)
        self.do_test_set_dsp()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
    def test_ip_set_dsp_same_slice_ingress_rep(self):
        self.MAC_PORT2_SLICE = ip_set_dsp.OUT_SLICE
        self.init_parameters(sdk.la_replication_paradigm_e_INGRESS)
        self.do_test_set_dsp()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_svi_unmatched_mc(unmatched_mc_ipv6_test, unmatched_mc_svi_test, unmatched_mc_base):

    def test_unmatched_mc_invalid_params(self):
        self.do_test_invalid_params()

    def test_unmatched_mc_default(self):
        self.do_test_unmatched_mc_default()

    def test_unmatched_mc(self):
        self.do_test_unmatched_mc()

    def test_unmatched_mc_long_addr(self):
        self.do_test_unmatched_mc_long_addr()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_svi_s_g_mc(ipv6_s_g_mc):
    RX_SVI_GID = 0x2a

    INPUT_PACKET_BASE = Ether(dst=ipv6_mc.get_mc_sa_addr_str(ipv6_s_g_mc.MC_GROUP_ADDR),
                              src=mc_base.SA.addr_str,
                              type=Ethertype.Dot1Q.value) / Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / IPv6(src=ipv6_mc.SIP.addr_str,
                                                                                                    dst=ipv6_s_g_mc.MC_GROUP_ADDR.addr_str,
                                                                                                    hlim=mc_base.TTL,
                                                                                                    plen=40) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_BASE = Ether(dst=ipv6_mc.get_mc_sa_addr_str(ipv6_s_g_mc.MC_GROUP_ADDR),
                                        src=T.TX_SVI_MAC.addr_str) / IPv6(src=ipv6_mc.SIP.addr_str,
                                                                          dst=ipv6_s_g_mc.MC_GROUP_ADDR.addr_str,
                                                                          hlim=mc_base.TTL - 1,
                                                                          plen=40) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_BASE_FWDCOPY2 = \
        Ether(dst=ipv6_mc.get_mc_sa_addr_str(ipv6_s_g_mc.MC_GROUP_ADDR), src=T.RX_SVI_MAC1.addr_str) / \
        IPv6(src=ipv6_mc.SIP.addr_str, dst=ipv6_s_g_mc.MC_GROUP_ADDR.addr_str, hlim=mc_base.TTL - 1, plen=40) / TCP() / Raw(load=RAW_PAYLOAD)

    INPUT_PACKET, EXPECTED_OUTPUT_PACKET = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)
    __, EXPECTED_OUTPUT_PACKET_FWDCOPY2 = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE_FWDCOPY2)
    EXPECTED_OUTPUT_PACKET_DEF = EXPECTED_OUTPUT_PACKET

    INPUT_PACKET_BASE3 = Ether(dst=ipv6_mc.get_mc_sa_addr_str(ipv6_s_g_mc.MC_GROUP_ADDR),
                               src=mc_base.SA.addr_str,
                               type=Ethertype.Dot1Q.value) / Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / IPv6(src=ipv6_mc.SIP3.addr_str,
                                                                                                     dst=ipv6_s_g_mc.MC_GROUP_ADDR.addr_str,
                                                                                                     hlim=mc_base.TTL,
                                                                                                     plen=40) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_BASE3 = Ether(dst=ipv6_mc.get_mc_sa_addr_str(ipv6_s_g_mc.MC_GROUP_ADDR),
                                         src=T.TX_SVI_MAC.addr_str) / IPv6(src=ipv6_mc.SIP3.addr_str,
                                                                           dst=ipv6_s_g_mc.MC_GROUP_ADDR.addr_str,
                                                                           hlim=mc_base.TTL - 1,
                                                                           plen=40) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_BASE3_FWDCOPY2 = \
        Ether(dst=ipv6_mc.get_mc_sa_addr_str(ipv6_s_g_mc.MC_GROUP_ADDR), src=T.RX_SVI_MAC.addr_str) / \
        IPv6(src=ipv6_mc.SIP3.addr_str, dst=ipv6_s_g_mc.MC_GROUP_ADDR.addr_str, hlim=mc_base.TTL - 1, plen=40) / TCP() / Raw(load=RAW_PAYLOAD)

    INPUT_PACKET3, EXPECTED_OUTPUT_PACKET3 = pad_input_and_output_packets(INPUT_PACKET_BASE3, EXPECTED_OUTPUT_PACKET_BASE3)
    __, EXPECTED_OUTPUT_PACKET3_FWDCOPY2 = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE3_FWDCOPY2)
    EXPECTED_OUTPUT_PACKET_DEF3 = EXPECTED_OUTPUT_PACKET3

    EXPECTED_OUTPUT_PACKET_SNOOP = \
        Ether(dst=mc_base.HOST_MAC_ADDR, src=mc_base.PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
        Dot1Q(prio=0, id=0, vlan=mc_base.MIRROR_VLAN, type=Ethertype.Punt.value) / \
        Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
             fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV6_COLLAPSED_MC,
             next_header_offset=0,
             source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
             code=mc_base.MIRROR_CMD_INGRESS_GID,
             source_sp=T.RX_SYS_PORT_GID,
             destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
             source_lp=T.RX_SVI_GID,
             destination_lp=0,
             relay_id=T.VRF_GID,
             lpts_flow_type=0) / \
        INPUT_PACKET

    EXPECTED_OUTPUT_PACKET_SNOOP3 = \
        Ether(dst=mc_base.HOST_MAC_ADDR, src=mc_base.PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
        Dot1Q(prio=0, id=0, vlan=mc_base.MIRROR_VLAN, type=Ethertype.Punt.value) / \
        Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
             fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV6_COLLAPSED_MC,
             next_header_offset=0,
             source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
             code=mc_base.MIRROR_CMD_INGRESS_GID,
             source_sp=T.RX_SYS_PORT_GID1,
             destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
             source_lp=T.RX_SVI_GID1,
             destination_lp=0,
             relay_id=T.VRF_GID,
             lpts_flow_type=0) / \
        INPUT_PACKET3

    l3_port_impl_class = T.ip_svi_base
    output_serdes = T.FIRST_SERDES_SVI
    svi = True

    def setUp(self):
         # MATILDA_SAVE -- need review
        if mc_base.BRIDGE_SLICE not in self.device.get_used_slices():
            self.skipTest("In MATILDA model the tested slice has been deactivated, thus the test is shkiped.")
            return
        mc_base.rechoose_odd_inject_slice(self.device)

        ipv6_s_g_mc.setUp(self)
        self.topology.rx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)
        self.topology.rx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)
        self.topology.rx_svi1.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)

        # Create port in rx_svi to receive forward/bridge copies
        self.eth_port1 = T.ethernet_port(
            self,
            self.device,
            mc_base.BRIDGE_SLICE,
            mc_base.BRIDGE_IFG,
            mc_base.BRIDGE_SYS_PORT1_GID,
            mc_base.BRIDGE_SERDES1,
            mc_base.BRIDGE_SERDES1 + 1)
        self.ac_port1 = T.l2_ac_port(self, self.device, mc_base.BRIDGE_AC_PORT1_GID, None, self.topology.rx_switch,
                                     self.eth_port1, T.RX_MAC, T.RX_L2_AC_PORT_VID1, T.RX_L2_AC_PORT_VID2)
        self.mc_group.add(self.l3_port_impl.rx_port.hld_obj, self.ac_port1.hld_obj, self.eth_port1.sys_port.hld_obj)

        self.rxsw_floodset = self.device.create_l2_multicast_group(mc_base.MC_GROUP_GID + 5, sdk.la_replication_paradigm_e_EGRESS)
        self.assertIsNotNone(self.rxsw_floodset)
        self.rxsw_floodset.add(self.ac_port1.hld_obj, self.eth_port1.sys_port.hld_obj)
        self.topology.rx_switch.hld_obj.set_flood_destination(self.rxsw_floodset)

        self.rxsw_mrouter = self.device.create_l2_multicast_group(mc_base.MC_GROUP_GID + 6, sdk.la_replication_paradigm_e_EGRESS)
        self.rxsw_mrouter.add(self.ac_port1.hld_obj, self.eth_port1.sys_port.hld_obj)

        self.topology.rx_switch.hld_obj.set_ipv6_multicast_enabled(True)
        self.rxsw_snoop = self.device.create_l2_multicast_group(mc_base.MC_GROUP_GID + 7, sdk.la_replication_paradigm_e_EGRESS)
        self.rxsw_snoop.add(self.ac_port1.hld_obj, self.eth_port1.sys_port.hld_obj)

        # Create port in rx_svi1 to receive forward/bridge copies
        self.eth_port2 = T.ethernet_port(
            self,
            self.device,
            mc_base.BRIDGE_SLICE,
            mc_base.BRIDGE_IFG,
            mc_base.BRIDGE_SYS_PORT2_GID,
            mc_base.BRIDGE_SERDES2,
            mc_base.BRIDGE_SERDES2 + 1)
        self.ac_port2 = T.l2_ac_port(self, self.device, mc_base.BRIDGE_AC_PORT2_GID, None, self.topology.rx_switch1,
                                     self.eth_port2, T.RX_MAC, T.RX_L2_AC_PORT_VID1, T.RX_L2_AC_PORT_VID2)
        self.mc_group.add(self.l3_port_impl.rx_port1.hld_obj, self.ac_port2.hld_obj, self.eth_port2.sys_port.hld_obj)

        self.rxsw1_floodset = self.device.create_l2_multicast_group(mc_base.MC_GROUP_GID + 8, sdk.la_replication_paradigm_e_EGRESS)
        self.assertIsNotNone(self.rxsw1_floodset)
        self.rxsw1_floodset.add(self.ac_port2.hld_obj, self.eth_port2.sys_port.hld_obj)
        self.topology.rx_switch1.hld_obj.set_flood_destination(self.rxsw1_floodset)

        self.rxsw1_mrouter = self.device.create_l2_multicast_group(mc_base.MC_GROUP_GID + 9, sdk.la_replication_paradigm_e_EGRESS)
        self.rxsw1_mrouter.add(self.ac_port2.hld_obj, self.eth_port2.sys_port.hld_obj)

        self.topology.rx_switch1.hld_obj.set_ipv6_multicast_enabled(True)
        self.rxsw1_snoop = self.device.create_l2_multicast_group(mc_base.MC_GROUP_GID + 10, sdk.la_replication_paradigm_e_EGRESS)
        self.rxsw1_snoop.add(self.ac_port2.hld_obj, self.eth_port2.sys_port.hld_obj)

    #(s,g)hit, none rpf, Action: Forward and bridge
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    def test_route_sg_nonerpf(self):
        self.rpf_intf = None
        self.rpf_intf3 = None
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route()

    #(s,g)hit, none rpf, Action: Forward and bridge
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_sg_nonerpf_ir(self):
        self.rpf_intf = None
        self.rpf_intf3 = None
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route_ir()

    #(s,g)hit, rpf-fail, Action: Bridge (punt_on_rpf_fail set as false)
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_sg_rpffail(self):
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port1.hld_obj)
        self.mc_group.remove(self.l3_port_impl.rx_port1.hld_obj, self.ac_port2.hld_obj)
        self.rpffail = True

        self.trap = True
        self.rpf_intf = self.topology.tx_l3_ac_reg.hld_obj
        self.is_mcast_route_hit = True
        self.rpf_intf3 = self.topology.tx_l3_ac_def.hld_obj
        self.do_test_route()

    #(s,g)hit, rpf-fail, Action: Bridge (punt_on_rpf_fail set as false)
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_sg_rpffail_ir(self):
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port1.hld_obj)
        self.mc_group.remove(self.l3_port_impl.rx_port1.hld_obj, self.ac_port2.hld_obj)
        self.rpffail = True

        self.trap = True
        self.rpf_intf = self.topology.tx_l3_ac_reg.hld_obj
        self.is_mcast_route_hit = True
        self.rpf_intf3 = self.topology.tx_l3_ac_def.hld_obj
        self.do_test_route_ir()

    #(s,g)hit, rpf-fail, Action: Snoop and bridge (punt_on_rpf_fail set as true)
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_sg_rpffail_punt(self):
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port1.hld_obj)
        self.mc_group.remove(self.l3_port_impl.rx_port1.hld_obj, self.ac_port2.hld_obj)
        self.rpffail = True

        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.tx_l3_ac_reg.hld_obj
        snoop_packet3 = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP3,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf3 = self.topology.tx_l3_ac_def.hld_obj
        self.trap = True
        self.is_mcast_route_hit = True
        self.do_test_route(extra_packet=snoop_packet, extra_packet3=snoop_packet3, punt_on_rpf_fail=True)

    #(s,g)hit, rpf-fail, Action: Snoop and bridge (punt_on_rpf_fail set as true)
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_sg_rpffail_punt_ir(self):
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port1.hld_obj)
        self.mc_group.remove(self.l3_port_impl.rx_port1.hld_obj, self.ac_port2.hld_obj)
        self.rpffail = True

        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.tx_l3_ac_reg.hld_obj
        snoop_packet3 = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP3,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf3 = self.topology.tx_l3_ac_def.hld_obj
        self.trap = True
        self.is_mcast_route_hit = True
        self.do_test_route_ir(extra_packet=snoop_packet, extra_packet3=snoop_packet3, punt_on_rpf_fail=True)

    #(s,g)hit, rpf-pass, Action: Forward and bridge
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    def test_route_sg_rpfpass(self):
        self.rpf_intf = self.topology.rx_svi.hld_obj
        self.rpf_intf3 = self.topology.rx_svi1.hld_obj
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route()

    #(s,g)hit, rpf-pass, Action: Forward and bridge
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    def test_route_sg_rpfpass_ir(self):
        self.rpf_intf = self.topology.rx_svi.hld_obj
        self.rpf_intf3 = self.topology.rx_svi1.hld_obj
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route_ir()

    #(s,g)hit, rpf-pass, Action: Forward and bridge
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_sg_rpf_pass_punt_on_rpf_fail_true(self):
        self.rpf_intf = self.topology.rx_svi.hld_obj
        self.rpf_intf3 = self.topology.rx_svi1.hld_obj
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route(punt_on_rpf_fail=True)

    #(s,g)hit, rpf-pass, Action: Forward and bridge
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_sg_rpf_pass_punt_on_rpf_fail_true_ir(self):
        self.rpf_intf = self.topology.rx_svi.hld_obj
        self.rpf_intf3 = self.topology.rx_svi1.hld_obj
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route_ir(punt_on_rpf_fail=True)

    def get_tx_l2_port(self):
        return self.topology.tx_l2_ac_port_reg.hld_obj

    def get_tx_l2_port_def(self):
        return self.topology.tx_l2_ac_port_def.hld_obj

    def get_tx_sys_port(self):
        return self.topology.tx_svi_eth_port_reg.sys_port.hld_obj

    def get_tx_sys_port_def(self):
        return self.topology.tx_svi_eth_port_def.sys_port.hld_obj


@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
class ip_multicast_group_ingress_replication(sdk_multi_test_case_base):
    MC_GROUP_ADDR = T.ipv4_addr('225.1.2.3')
    MC_GROUP_GID = 0x13

    def setUp(self):
        super().setUp()

    def test_ipmcg_ingress(self):
        # test1 - creation
        self.ingress_ipmcg = self.device.create_ip_multicast_group(self.MC_GROUP_GID, sdk.la_replication_paradigm_e_INGRESS)
        ingress_ipmcg2 = self.device.get_ip_multicast_group(self.MC_GROUP_GID)
        self.assertEqual(ingress_ipmcg2.this, self.ingress_ipmcg.this)

        with self.assertRaises(sdk.ExistException):
            self.egress_ipmcg = self.device.create_ip_multicast_group(self.MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)
        with self.assertRaises(sdk.ExistException):
            self.egress_l2mcg = self.device.create_l2_multicast_group(self.MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)

        # ingress replication not implemented for l2 and mpls mcg
        with self.assertRaises(sdk.NotImplementedException):
            self.ingress_l2mcg = self.device.create_l2_multicast_group(self.MC_GROUP_GID + 1,
                                                                       sdk.la_replication_paradigm_e_INGRESS)
        with self.assertRaises(sdk.NotImplementedException):
            self.ingress_mpls_mcg = self.device.create_mpls_multicast_group(self.MC_GROUP_GID + 1,
                                                                            sdk.la_replication_paradigm_e_INGRESS)

        # test2 - add/remove
        self.mem1_ipmcg = self.device.create_ip_multicast_group(self.MC_GROUP_GID + 1, sdk.la_replication_paradigm_e_EGRESS)
        self.mem2_l2mcg = self.device.create_l2_multicast_group(self.MC_GROUP_GID + 2, sdk.la_replication_paradigm_e_EGRESS)
        self.egress_mplsmcg = self.device.create_mpls_multicast_group(self.MC_GROUP_GID + 3, sdk.la_replication_paradigm_e_EGRESS)
        self.ingress_ipmcg.add(self.mem1_ipmcg)
        self.ingress_ipmcg.add(self.topology.rx_svi.hld_obj, self.mem2_l2mcg)
        self.ingress_ipmcg.add(self.egress_mplsmcg)
        self.ingress_ipmcg.add(self.topology.tx_l3_ac_reg.hld_obj, None, self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj)
        self.ingress_ipmcg.add(self.topology.rx_svi.hld_obj, self.topology.rx_l2_ac_port.hld_obj,
                               self.topology.rx_eth_port.sys_port.hld_obj)
        with self.assertRaises(sdk.InvalException):
            self.ingress_ipmcg.add(self.topology.tx_svi.hld_obj, self.mem2_l2mcg)

        # test3 - get size /get paradigm /get_gid
        size = self.ingress_ipmcg.get_size()
        self.assertEqual(size, 5)
        res_replication_paradigm = self.ingress_ipmcg.get_replication_paradigm()
        self.assertEqual(res_replication_paradigm, sdk.la_replication_paradigm_e_INGRESS)
        gid = self.ingress_ipmcg.get_gid()
        self.assertEqual(gid, self.MC_GROUP_GID)

        # test4 - get_member
        (ipmcg_meminfo) = self.ingress_ipmcg.get_member(0)
        self.assertIsNone(ipmcg_meminfo.l3_port)
        self.assertIsNone(ipmcg_meminfo.l2_port)
        self.assertIsNone(ipmcg_meminfo.l2_mcg)
        self.assertIsNone(ipmcg_meminfo.mpls_mcg)
        self.assertEqual(ipmcg_meminfo.ip_mcg.this, self.mem1_ipmcg.this)

        (ipmcg_meminfo) = self.ingress_ipmcg.get_member(1)
        self.assertEqual(ipmcg_meminfo.l3_port.this, self.topology.rx_svi.hld_obj.this)
        self.assertIsNone(ipmcg_meminfo.l2_port)
        self.assertEqual(ipmcg_meminfo.l2_mcg.this, self.mem2_l2mcg.this)
        self.assertIsNone(ipmcg_meminfo.ip_mcg)
        self.assertIsNone(ipmcg_meminfo.mpls_mcg)

        (ipmcg_meminfo) = self.ingress_ipmcg.get_member(2)
        self.assertIsNone(ipmcg_meminfo.l3_port)
        self.assertIsNone(ipmcg_meminfo.l2_port)
        self.assertIsNone(ipmcg_meminfo.l2_mcg)
        self.assertEqual(ipmcg_meminfo.mpls_mcg.this, self.egress_mplsmcg.this)

        (ipmcg_meminfo) = self.ingress_ipmcg.get_member(3)
        self.assertEqual(ipmcg_meminfo.l3_port.this, self.topology.tx_l3_ac_reg.hld_obj.this)
        self.assertIsNone(ipmcg_meminfo.l2_port)
        self.assertIsNone(ipmcg_meminfo.l2_mcg)
        self.assertIsNone(ipmcg_meminfo.ip_mcg)
        self.assertIsNone(ipmcg_meminfo.mpls_mcg)

        (ipmcg_meminfo) = self.ingress_ipmcg.get_member(4)
        self.assertEqual(ipmcg_meminfo.l3_port.this, self.topology.rx_svi.hld_obj.this)
        self.assertEqual(ipmcg_meminfo.l2_port.this, self.topology.rx_l2_ac_port.hld_obj.this)
        self.assertIsNone(ipmcg_meminfo.l2_mcg)
        self.assertIsNone(ipmcg_meminfo.ip_mcg)
        self.assertIsNone(ipmcg_meminfo.mpls_mcg)

        # test5 - remove members
        self.ingress_ipmcg.remove(self.topology.rx_svi.hld_obj, self.mem2_l2mcg)
        self.ingress_ipmcg.remove(self.mem1_ipmcg)
        self.ingress_ipmcg.remove(self.topology.tx_l3_ac_reg.hld_obj, None)
        self.ingress_ipmcg.remove(self.topology.rx_svi.hld_obj, self.topology.rx_l2_ac_port.hld_obj)
        self.ingress_ipmcg.remove(self.egress_mplsmcg)

        self.device.destroy(self.ingress_ipmcg)
        self.device.destroy(self.mem1_ipmcg)
        self.device.destroy(self.mem2_l2mcg)


@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
@unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
@unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
@unittest.skipIf(decor.is_auto_warm_boot_enabled(), "Skip in auto-WB sanity")
class test_mpls_ingress_replication(ir_base):
    def setUp(self):
        super().setUp()
        self.ipv4 = True

    def test_l3ac_ingress_rep_mpls(self):
        self.do_test_l3ac_ingress_rep_mpls()

    def test_l3ac_ingress_rep_mpls_ttl_eq_1(self):
        self.do_test_l3ac_ingress_rep_mpls_ttl_eq_1()


@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
@unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
@unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
@unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
@unittest.skipIf(decor.is_auto_warm_boot_enabled(), "Skip in auto-WB sanity")
class test_ipv4_ingress_replication(ir_base):
    def setUp(self):
        super().setUp()
        self.ipv4 = True

    def test_l3ac_egress_rep(self):
        self.do_test_l3ac_egress_rep()

    def test_svi_egress_rep(self):
        self.do_test_svi_egress_rep()

    def test_ingress_rep(self):
        self.do_test_ingress_rep()

    def test_l3ac_ingress_rep(self):
        self.do_test_l3ac_ingress_rep()

    def test_l3ac_ingress_rep_with_ports(self):
        self.do_test_l3ac_ingress_rep_with_ports()

    def test_svi_ingress_rep(self):
        self.do_test_svi_ingress_rep()

    def test_svi_ingress_rep_with_ports(self):
        self.do_test_svi_ingress_rep_with_ports()

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    def test_mcg_counter(self):
        self.do_test_mcg_counter()

    def test_l2mcg_set_dsp(self):
        self.do_test_set_dsp_same_slice()
        self.do_test_set_dsp_different_slice()

    def test_l2mcg_ref_count(self):
        self.do_test_l2mcg_refcount()

    def test_flood_set(self):
        self.do_test_flood_set()

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    def test_l2mc_ir(self):
        self.do_test_l2mc_ir()

    def test_set_rep_paradigm(self):
        self.do_test_set_rep_paradigm()

    def test_set_rep_paradigm_empty(self):
        self.do_test_set_rep_paradigm_empty()


@unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails")
@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
@unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
class test_ipv6_ingress_replication(ir_base):
    def setUp(self):
        super().setUp()
        self.ipv4 = False

    def test_l3ac_egress_rep(self):
        self.do_test_l3ac_egress_rep()

    def test_svi_egress_rep(self):
        self.do_test_svi_egress_rep()

    def test_ingress_rep(self):
        self.do_test_ingress_rep()

    def test_l3ac_ingress_rep(self):
        self.do_test_l3ac_ingress_rep()

    def test_l3ac_ingress_rep_with_ports(self):
        self.do_test_l3ac_ingress_rep_with_ports()

    def test_svi_ingress_rep(self):
        self.do_test_svi_ingress_rep()

    def test_svi_ingress_rep_with_ports(self):
        self.do_test_svi_ingress_rep_with_ports()

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    def test_mcg_counter(self):
        self.do_test_mcg_counter()

    def test_l2mcg_set_dsp(self):
        self.do_test_set_dsp_same_slice()
        self.do_test_set_dsp_different_slice()

    def test_l2mcg_ref_count(self):
        self.do_test_l2mcg_refcount()

    def test_flood_set(self):
        self.do_test_flood_set()

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    def test_l2mc_ir(self):
        self.do_test_l2mc_ir()

    def test_set_rep_paradigm(self):
        self.do_test_set_rep_paradigm()

    def test_set_rep_paradigm_empty(self):
        self.do_test_set_rep_paradigm_empty()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
def setUpModule():
    sdk_multi_test_case_base.initialize()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
def tearDownModule():
    sdk_multi_test_case_base.destroy()


if __name__ == '__main__':
    unittest.main()
