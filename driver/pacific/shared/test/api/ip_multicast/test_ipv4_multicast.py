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
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv4_known_multicast_routing_pkt_count(ipv4_s_g_mc):

    INPUT_PACKET_BASE = \
        Ether(dst=ipv4_mc.get_mc_sa_addr_str(ipv4_s_g_mc.MC_GROUP_ADDR), src=mc_base.SA.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
        IP(src=ipv4_mc.SIP.addr_str, dst=ipv4_s_g_mc.MC_GROUP_ADDR.addr_str, ttl=mc_base.TTL) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_BASE = Ether(dst=ipv4_mc.get_mc_sa_addr_str(ipv4_s_g_mc.MC_GROUP_ADDR),
                                        src=T.TX_SVI_MAC.addr_str) / IP(src=ipv4_mc.SIP.addr_str,
                                                                        dst=ipv4_s_g_mc.MC_GROUP_ADDR.addr_str,
                                                                        ttl=mc_base.TTL - 1) / TCP() / Raw(load=RAW_PAYLOAD)

    INPUT_PACKET, EXPECTED_OUTPUT_PACKET = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)
    EXPECTED_OUTPUT_PACKET_DEF = EXPECTED_OUTPUT_PACKET

    l3_port_impl_class = T.ip_svi_base
    output_serdes = T.FIRST_SERDES_SVI

    def setUp(self):
        ipv4_s_g_mc.setUp(self)

        self.topology.rx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    def test_route_pkt_count(self):
        self.do_test_route_pkt_count()

    def get_tx_l2_port(self):
        return self.topology.tx_l2_ac_port_reg.hld_obj

    def get_tx_l2_port_def(self):
        return self.topology.tx_l2_ac_port_def.hld_obj

    def get_tx_sys_port(self):
        return self.topology.tx_svi_eth_port_reg.sys_port.hld_obj

    def get_tx_sys_port_def(self):
        return self.topology.tx_svi_eth_port_def.sys_port.hld_obj


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv4_l3_ac_egress_member_punt(egress_member_punt_ipv4_test, egress_member_punt_l3_ac_test, egress_member_punt_base):

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_member_punt(self):
        self.do_test_egress_member_punt()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_member_punt_member_remove(self):
        self.do_test_egress_member_punt_member_remove()

    def test_egress_member_punt_member_get(self):
        self.do_test_egress_member_punt_member_get()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv4_l3_ac_g_mc_mtu(ipv4_g_mc):

    INPUT_PACKET_BASE = \
        Ether(dst=ipv4_mc.get_mc_sa_addr_str(ipv4_g_mc.MC_GROUP_ADDR), src=mc_base.SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IP(src=ipv4_mc.SIP.addr_str, dst=ipv4_g_mc.MC_GROUP_ADDR.addr_str, ttl=mc_base.TTL) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_BASE = Ether(dst=ipv4_mc.get_mc_sa_addr_str(ipv4_g_mc.MC_GROUP_ADDR),
                                        src=T.TX_L3_AC_REG_MAC.addr_str) / IP(src=ipv4_mc.SIP.addr_str,
                                                                              dst=ipv4_g_mc.MC_GROUP_ADDR.addr_str,
                                                                              ttl=mc_base.TTL - 1) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_DEF_BASE = \
        Ether(dst=ipv4_mc.get_mc_sa_addr_str(ipv4_g_mc.MC_GROUP_ADDR), src=T.TX_L3_AC_DEF_MAC.addr_str) / \
        IP(src=ipv4_mc.SIP.addr_str, dst=ipv4_g_mc.MC_GROUP_ADDR.addr_str, ttl=mc_base.TTL - 1) / TCP() / Raw(load=RAW_PAYLOAD)

    INPUT_PACKET, EXPECTED_OUTPUT_PACKET = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)
    __, EXPECTED_OUTPUT_PACKET_DEF = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_DEF_BASE)

    l3_port_impl_class = T.ip_l3_ac_base
    output_serdes = T.FIRST_SERDES_L3

    def test_route_mtu(self):
        self.do_test_route_mtu()

    def get_tx_l2_port(self):
        return None

    def get_tx_l2_port_def(self):
        return None

    def get_tx_sys_port(self):
        return self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj

    def get_tx_sys_port_def(self):
        return self.topology.tx_l3_ac_eth_port_def.sys_port.hld_obj


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv4_l3_ac_g_mc_with_punt_mtu(ipv4_g_mc):

    PUNT_SLICE = T.get_device_slice(2)
    PUNT_IFG = 0
    PUNT_SERDES = T.get_device_first_serdes(8)
    PUNT_SYS_PORT_GID = T.MIN_SYSTEM_PORT_GID
    PI_PORT_MAC = T.mac_addr('ab:ab:ab:ab:ab:ab')
    HOST_MAC_ADDR = T.mac_addr('cd:cd:cd:cd:cd:cd')
    PUNT_DEST_GID = 0x13
    PUNT_DEST_VID = 0x13
    MIRROR_CMD_GID = 9
    MIRROR_GID_INGRESS_OFFSET = 32
    MIRROR_GID_EGRESS_OFFSET = 0
    MIRROR_CMD_INGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_INGRESS_OFFSET
    MIRROR_CMD_EGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_EGRESS_OFFSET
    MIRROR_VLAN = 19

    INPUT_PACKET_BASE = \
        Ether(dst=ipv4_mc.get_mc_sa_addr_str(ipv4_g_mc.MC_GROUP_ADDR), src=mc_base.SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IP(src=ipv4_mc.SIP.addr_str, dst=ipv4_g_mc.MC_GROUP_ADDR.addr_str, ttl=mc_base.TTL) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_BASE = Ether(dst=ipv4_mc.get_mc_sa_addr_str(ipv4_g_mc.MC_GROUP_ADDR),
                                        src=T.TX_L3_AC_REG_MAC.addr_str) / IP(src=ipv4_mc.SIP.addr_str,
                                                                              dst=ipv4_g_mc.MC_GROUP_ADDR.addr_str,
                                                                              ttl=mc_base.TTL - 1) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_DEF_BASE = \
        Ether(dst=ipv4_mc.get_mc_sa_addr_str(ipv4_g_mc.MC_GROUP_ADDR), src=T.TX_L3_AC_DEF_MAC.addr_str) / \
        IP(src=ipv4_mc.SIP.addr_str, dst=ipv4_g_mc.MC_GROUP_ADDR.addr_str, ttl=mc_base.TTL - 1) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_PUNT_BASE = \
        Ether(dst=HOST_MAC_ADDR.addr_str, src=PI_PORT_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1Q(prio=0, id=0, vlan=PUNT_DEST_VID, type=Ethertype.Punt.value) / \
        Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_IPV4, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
             next_header_offset=0,
             source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
             code=MIRROR_CMD_INGRESS_GID,
             source_sp=T.RX_SYS_PORT_GID,
             destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
             source_lp=T.RX_L3_AC_GID,
             destination_lp=0,  # bogus number, not known at ingress
             relay_id=T.VRF_GID, lpts_flow_type=0) / \
        Ether(dst=ipv4_mc.get_mc_sa_addr_str(ipv4_g_mc.MC_GROUP_ADDR), src=mc_base.SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IP(src=ipv4_mc.SIP.addr_str, dst=ipv4_g_mc.MC_GROUP_ADDR.addr_str, ttl=mc_base.TTL) / TCP() / Raw(load=RAW_PAYLOAD)

    INPUT_PACKET, EXPECTED_OUTPUT_PACKET = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)
    __, EXPECTED_OUTPUT_PACKET_DEF = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_DEF_BASE)
    __, EXPECTED_OUTPUT_PACKET_PUNT = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_PUNT_BASE)

    l3_port_impl_class = T.ip_l3_ac_base
    output_serdes = T.FIRST_SERDES_L3

    def setUp(self):
        # MATILDA_SAVE -- need review
        if (self.PUNT_SLICE not in self.device.get_used_slices()):
            self.PUNT_SLICE = T.choose_active_slices(self.device,
                                                     self.PUNT_SLICE, [4, 2])

        ipv4_g_mc.setUp(self)

        self.pi_port = T.punt_inject_port(
            self,
            self.device,
            self.PUNT_SLICE,
            self.PUNT_IFG,
            self.PUNT_SYS_PORT_GID,
            self.PUNT_SERDES,
            self.PI_PORT_MAC.addr_str)
        sampling_rate = 1.0
        mirror_cmd = T.create_l2_mirror_command(
            self.device,
            self.MIRROR_CMD_INGRESS_GID,
            self.pi_port,
            self.HOST_MAC_ADDR.addr_str,
            self.MIRROR_VLAN,
            sampling_rate)
        self.device.clear_trap_configuration(sdk.LA_EVENT_L3_IP_MC_G_PUNT_MEMBER)
        self.device.set_snoop_configuration(sdk.LA_EVENT_L3_IP_MC_G_PUNT_MEMBER, 0, False, False, mirror_cmd)

    def test_route_mtu(self):
        punt_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_PUNT,
            self.PUNT_SLICE,
            self.PUNT_IFG,
            self.PUNT_SERDES)
        self.do_test_route_mtu(extra_packet=punt_packet, punt_and_forward=True)

    def get_tx_l2_port(self):
        return None

    def get_tx_l2_port_def(self):
        return None

    def get_tx_sys_port(self):
        return self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj

    def get_tx_sys_port_def(self):
        return self.topology.tx_l3_ac_eth_port_def.sys_port.hld_obj


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv4_l3_ac_g_mc_with_punt_pci(ipv4_g_mc):

    PUNT_SLICE = T.get_device_slice(2)
    PUNT_IFG = 0
    PUNT_SERDES = 24 if decor.is_gibraltar() else 18
    PUNT_SYS_PORT_GID = T.MIN_SYSTEM_PORT_GID
    PI_PORT_MAC = T.mac_addr('ab:ab:ab:ab:ab:ab')
    HOST_MAC_ADDR = T.mac_addr('cd:cd:cd:cd:cd:cd')
    PUNT_DEST_GID = 0x13
    PUNT_DEST_VID = 0x13
    MIRROR_CMD_GID = 9
    MIRROR_GID_INGRESS_OFFSET = 32
    MIRROR_GID_EGRESS_OFFSET = 0
    MIRROR_CMD_INGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_INGRESS_OFFSET
    MIRROR_CMD_EGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_EGRESS_OFFSET
    MIRROR_VLAN = 19
    svi = False

    INPUT_PACKET_BASE = \
        Ether(dst=ipv4_mc.get_mc_sa_addr_str(ipv4_g_mc.MC_GROUP_ADDR), src=mc_base.SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IP(src=ipv4_mc.SIP.addr_str, dst=ipv4_g_mc.MC_GROUP_ADDR.addr_str, ttl=mc_base.TTL) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_BASE = Ether(dst=ipv4_mc.get_mc_sa_addr_str(ipv4_g_mc.MC_GROUP_ADDR),
                                        src=T.TX_L3_AC_REG_MAC.addr_str) / IP(src=ipv4_mc.SIP.addr_str,
                                                                              dst=ipv4_g_mc.MC_GROUP_ADDR.addr_str,
                                                                              ttl=mc_base.TTL - 1) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_DEF_BASE = \
        Ether(dst=ipv4_mc.get_mc_sa_addr_str(ipv4_g_mc.MC_GROUP_ADDR), src=T.TX_L3_AC_DEF_MAC.addr_str) / \
        IP(src=ipv4_mc.SIP.addr_str, dst=ipv4_g_mc.MC_GROUP_ADDR.addr_str, ttl=mc_base.TTL - 1) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_PUNT_BASE = \
        Ether(dst=HOST_MAC_ADDR.addr_str, src=T.INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
        Dot1Q(prio=0, id=0, vlan=PUNT_DEST_VID, type=Ethertype.Punt.value) / \
        Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_IPV4, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
             next_header_offset=0,
             source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
             code=MIRROR_CMD_INGRESS_GID,
             source_sp=T.RX_SYS_PORT_GID,
             destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
             source_lp=T.RX_L3_AC_GID,
             destination_lp=0,  # bogus number, not known at ingress
             relay_id=T.VRF_GID, lpts_flow_type=0) / \
        Ether(dst=ipv4_mc.get_mc_sa_addr_str(ipv4_g_mc.MC_GROUP_ADDR), src=mc_base.SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IP(src=ipv4_mc.SIP.addr_str, dst=ipv4_g_mc.MC_GROUP_ADDR.addr_str, ttl=mc_base.TTL) / TCP() / Raw(load=RAW_PAYLOAD)

    INPUT_PACKET, EXPECTED_OUTPUT_PACKET = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)
    __, EXPECTED_OUTPUT_PACKET_DEF = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_DEF_BASE)
    __, EXPECTED_OUTPUT_PACKET_PUNT = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_PUNT_BASE)

    l3_port_impl_class = T.ip_l3_ac_base
    output_serdes = T.FIRST_SERDES_L3

    def setUp(self):
        # MATILDA_SAVE -- need review
        if (self.PUNT_SLICE not in self.device.get_used_slices()):
            self.PUNT_SLICE = T.choose_active_slices(self.device,
                                                     self.PUNT_SLICE, [4, 2])

        ipv4_g_mc.setUp(self)

        sampling_rate = 1.0
        mirror_cmd = T.create_l2_mirror_command(
            self.device,
            self.MIRROR_CMD_INGRESS_GID,
            self.topology.inject_ports[self.PUNT_SLICE],
            self.HOST_MAC_ADDR.addr_str,
            self.MIRROR_VLAN,
            sampling_rate)
        self.device.clear_trap_configuration(sdk.LA_EVENT_L3_IP_MC_G_PUNT_MEMBER)
        self.device.set_snoop_configuration(sdk.LA_EVENT_L3_IP_MC_G_PUNT_MEMBER, 0, False, False, mirror_cmd)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route(self):
        punt_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_PUNT,
            self.PUNT_SLICE,
            self.PUNT_IFG,
            self.PUNT_SERDES)
        if T.is_matilda_model(self.device):
            return
        self.do_test_route(extra_packet=punt_packet, punt_and_forward=True)

    def get_tx_l2_port(self):
        return None

    def get_tx_l2_port_def(self):
        return None

    def get_tx_sys_port(self):
        return self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj

    def get_tx_sys_port_def(self):
        return self.topology.tx_l3_ac_eth_port_def.sys_port.hld_obj


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv4_l3_ac_g_mc_with_punt(ipv4_g_mc):

    PUNT_SLICE = T.get_device_slice(2)
    PUNT_IFG = 0
    PUNT_SERDES = T.get_device_first_serdes(8)
    PUNT_SYS_PORT_GID = T.MIN_SYSTEM_PORT_GID
    PI_PORT_MAC = T.mac_addr('ab:ab:ab:ab:ab:ab')
    HOST_MAC_ADDR = T.mac_addr('cd:cd:cd:cd:cd:cd')
    PUNT_DEST_GID = 0x13
    PUNT_DEST_VID = 0x13
    MIRROR_CMD_GID = 9
    MIRROR_GID_INGRESS_OFFSET = 32
    MIRROR_GID_EGRESS_OFFSET = 0
    MIRROR_CMD_INGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_INGRESS_OFFSET
    MIRROR_CMD_EGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_EGRESS_OFFSET
    MIRROR_VLAN = 19
    svi = False

    INPUT_PACKET_BASE = \
        Ether(dst=ipv4_mc.get_mc_sa_addr_str(ipv4_g_mc.MC_GROUP_ADDR), src=mc_base.SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IP(src=ipv4_mc.SIP.addr_str, dst=ipv4_g_mc.MC_GROUP_ADDR.addr_str, ttl=mc_base.TTL) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_BASE = Ether(dst=ipv4_mc.get_mc_sa_addr_str(ipv4_g_mc.MC_GROUP_ADDR),
                                        src=T.TX_L3_AC_REG_MAC.addr_str) / IP(src=ipv4_mc.SIP.addr_str,
                                                                              dst=ipv4_g_mc.MC_GROUP_ADDR.addr_str,
                                                                              ttl=mc_base.TTL - 1) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_DEF_BASE = \
        Ether(dst=ipv4_mc.get_mc_sa_addr_str(ipv4_g_mc.MC_GROUP_ADDR), src=T.TX_L3_AC_DEF_MAC.addr_str) / \
        IP(src=ipv4_mc.SIP.addr_str, dst=ipv4_g_mc.MC_GROUP_ADDR.addr_str, ttl=mc_base.TTL - 1) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_PUNT_BASE = \
        Ether(dst=HOST_MAC_ADDR.addr_str, src=PI_PORT_MAC.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1Q(prio=0, id=0, vlan=PUNT_DEST_VID, type=Ethertype.Punt.value) / \
        Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_IPV4, fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
             next_header_offset=0,
             source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
             code=MIRROR_CMD_INGRESS_GID,
             source_sp=T.RX_SYS_PORT_GID,
             destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
             source_lp=T.RX_L3_AC_GID,
             destination_lp=0,  # bogus number, not known at ingress
             relay_id=T.VRF_GID, lpts_flow_type=0) / \
        Ether(dst=ipv4_mc.get_mc_sa_addr_str(ipv4_g_mc.MC_GROUP_ADDR), src=mc_base.SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IP(src=ipv4_mc.SIP.addr_str, dst=ipv4_g_mc.MC_GROUP_ADDR.addr_str, ttl=mc_base.TTL) / TCP() / Raw(load=RAW_PAYLOAD)

    INPUT_PACKET, EXPECTED_OUTPUT_PACKET = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)
    __, EXPECTED_OUTPUT_PACKET_DEF = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_DEF_BASE)
    __, EXPECTED_OUTPUT_PACKET_PUNT = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_PUNT_BASE)

    l3_port_impl_class = T.ip_l3_ac_base
    output_serdes = T.FIRST_SERDES_L3

    def setUp(self):
        # MATILDA_SAVE -- need review
        if (self.PUNT_SLICE not in self.device.get_used_slices()):
            self.PUNT_SLICE = T.choose_active_slices(self.device,
                                                     self.PUNT_SLICE, [4, 2])

        ipv4_g_mc.setUp(self)

        self.pi_port = T.punt_inject_port(
            self,
            self.device,
            self.PUNT_SLICE,
            self.PUNT_IFG,
            self.PUNT_SYS_PORT_GID,
            self.PUNT_SERDES,
            self.PI_PORT_MAC.addr_str)
        sampling_rate = 1.0
        mirror_cmd = T.create_l2_mirror_command(
            self.device,
            self.MIRROR_CMD_INGRESS_GID,
            self.pi_port,
            self.HOST_MAC_ADDR.addr_str,
            self.MIRROR_VLAN,
            sampling_rate)
        self.device.clear_trap_configuration(sdk.LA_EVENT_L3_IP_MC_G_PUNT_MEMBER)
        self.device.set_snoop_configuration(sdk.LA_EVENT_L3_IP_MC_G_PUNT_MEMBER, 0, False, False, mirror_cmd)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route(self):
        punt_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_PUNT,
            self.PUNT_SLICE,
            self.PUNT_IFG,
            self.PUNT_SERDES)
        if T.is_matilda_model(self.device):
            return
        self.do_test_route(extra_packet=punt_packet, punt_and_forward=True)

    def get_tx_l2_port(self):
        return None

    def get_tx_l2_port_def(self):
        return None

    def get_tx_sys_port(self):
        return self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj

    def get_tx_sys_port_def(self):
        return self.topology.tx_l3_ac_eth_port_def.sys_port.hld_obj


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv4_l3_ac_g_mc(ipv4_g_mc):
    l3_port_impl_class = T.ip_l3_ac_base
    output_serdes = T.FIRST_SERDES_L3
    ip_impl = ip_test_base.ipv4_test_base()
    svi = False

    def setUp(self):
        ipv4_g_mc.setUp(self)
        mc_base.rechoose_odd_inject_slice(self.device)
        # Init snoops and traps
        pi_port = T.punt_inject_port(self, self.device, mc_base.INJECT_SLICE, mc_base.INJECT_IFG, mc_base.INJECT_SP_GID,
                                     mc_base.INJECT_PIF_FIRST, mc_base.PUNT_INJECT_PORT_MAC_ADDR)
        punt_dest = T.create_l2_punt_destination(self, self.device, T.L2_PUNT_DESTINATION2_GID,
                                                 pi_port, mc_base.HOST_MAC_ADDR, mc_base.PUNT_VLAN)
        mirror_cmd = T.create_l2_mirror_command(self.device, mc_base.MIRROR_CMD_INGRESS_GID, pi_port,
                                                mc_base.HOST_MAC_ADDR, mc_base.MIRROR_VLAN)
        mc_base.initSnoopsAndTraps(self.device, punt_dest, mirror_cmd)
        self.topology.rx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)

        # Add subnet for DC pass
        subnet = self.ip_impl.build_prefix(ipv4_mc.SIP, length=16)
        self.ip_impl.add_subnet(self.topology.rx_l3_ac, subnet)

        # Add route with fec for DC fail
        nh = T.next_hop(self, self.device, mc_base.NH_GID, mc_base.NH_MAC, self.topology.rx_l3_ac)
        fec = T.fec(self, self.device, nh)
        prefix = self.ip_impl.build_prefix(ipv4_mc.SIP_FEC, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, fec, mc_base.PRIVATE_DATA)

    def construct_packet(self, mc_mac, source_ip):
        INPUT_PACKET_BASE = \
            Ether(dst=ipv4_mc.get_mc_sa_addr_str(mc_mac), src=mc_base.SA.addr_str, type=Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            IP(src=source_ip.addr_str, dst=mc_mac.addr_str, ttl=mc_base.TTL) / TCP() / Raw(load=RAW_PAYLOAD)

        EXPECTED_OUTPUT_PACKET_BASE = \
            Ether(dst=ipv4_mc.get_mc_sa_addr_str(mc_mac), src=T.TX_L3_AC_REG_MAC.addr_str) / \
            IP(src=source_ip.addr_str, dst=mc_mac.addr_str, ttl=mc_base.TTL - 1) / TCP() / Raw(load=RAW_PAYLOAD)

        EXPECTED_OUTPUT_PACKET_DEF_BASE = \
            Ether(dst=ipv4_mc.get_mc_sa_addr_str(mc_mac), src=T.TX_L3_AC_DEF_MAC.addr_str) / \
            IP(src=source_ip.addr_str, dst=mc_mac.addr_str, ttl=mc_base.TTL - 1) / TCP() / Raw(load=RAW_PAYLOAD)

        self.INPUT_PACKET, self.EXPECTED_OUTPUT_PACKET = pad_input_and_output_packets(
            INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)
        __, self.EXPECTED_OUTPUT_PACKET_DEF = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_DEF_BASE)

    def construct_punt_packet(self, trap_code):
        self.EXPECTED_OUTPUT_PACKET_PUNT = \
            Ether(dst=mc_base.HOST_MAC_ADDR, src=mc_base.PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=mc_base.PUNT_VLAN, type=Ethertype.Punt.value) / \
            Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                 fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
                 next_header_offset=len(Ether()) + 2 * len(Dot1Q()),
                 source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
                 code=trap_code,
                 source_sp=T.RX_SYS_PORT_GID,
                 destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                 source_lp=T.RX_L3_AC_GID,
                 destination_lp=trap_code,
                 relay_id=T.VRF_GID,
                 lpts_flow_type=0) / \
            self.INPUT_PACKET

    def construct_snoop_packet(self):
        self.EXPECTED_OUTPUT_PACKET_SNOOP = \
            Ether(dst=mc_base.HOST_MAC_ADDR, src=mc_base.PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=mc_base.MIRROR_VLAN, type=Ethertype.Punt.value) / \
            Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_IPV4,
                 fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
                 next_header_offset=0,
                 source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                 code=mc_base.MIRROR_CMD_INGRESS_GID,
                 source_sp=T.RX_SYS_PORT_GID,
                 destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                 source_lp=T.RX_L3_AC_GID,
                 destination_lp=0,
                 relay_id=T.VRF_GID,
                 lpts_flow_type=0) / \
            self.INPUT_PACKET

    # For all tests:
    # 1. construct input and expected output packets (with required mc_mac and sip)
    # 2. construct any expected cpu packets (trap or snoop packets)
    # 3. set the rpf value (for rpf pass or rpf fail)
    # 4. set trap boolean, if set to True, it is a trap otherwise snoop
    #    this value is used in base class to construct the expected_packets list
    # 5. set pcount - packet count
    #    this value is used in base class to verify the counters
    # The original cases with 'none' rpf are also maintained. They are considered
    # rpf pass cases with directly connected check pass or fail.
    #
    # For (*,g) miss cases, different mc mac is used.
    # For DC fail cases (directly connected check fail), different source ip is used.
    # For RPF fail cases, rx_l3_ac1 is used.

    def test_route_gmiss_dcfail(self):
        #(*,g) miss, dc fail: Action: drop
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR_MISS, ipv4_mc.SIP_DCFAIL)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False
        self.do_test_route()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_gmiss_dcfail_ir(self):
        #(*,g) miss, dc fail: Action: drop
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR_MISS, ipv4_mc.SIP_DCFAIL)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False
        self.do_test_route_ir()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "Failing in pl-compound, passing in master")
    def test_route_gmiss_dcfail_fec(self):
        #(*,g) miss, dc fail: Action: drop
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR_MISS, ipv4_mc.SIP_FEC)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False
        self.do_test_route()

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_gmiss_dcfail_fec_ir(self):
        #(*,g) miss, dc fail: Action: drop
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR_MISS, ipv4_mc.SIP_FEC)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False
        self.do_test_route_ir()

    def test_route_gmiss_dcpass(self):
        #(*,g) miss, dc pass: Action: punt
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR_MISS, ipv4_mc.SIP)
        self.construct_punt_packet(trap_code=sdk.LA_EVENT_L3_IP_MC_PUNT_DC_PASS)
        punt_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_PUNT,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False
        self.do_test_route(extra_packet=punt_packet)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_gmiss_dcpass_ir(self):
        #(*,g) miss, dc pass: Action: punt
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR_MISS, ipv4_mc.SIP)
        self.construct_punt_packet(trap_code=sdk.LA_EVENT_L3_IP_MC_PUNT_DC_PASS)
        punt_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_PUNT,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False
        self.do_test_route_ir(extra_packet=punt_packet)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_nonerpf_dcfail(self):
        #(*,g) none rpf, dc fail: Action: forward
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_DCFAIL)
        self.rpf_intf = None
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_nonerpf_dcfail_ir(self):
        #(*,g) none rpf, dc fail: Action: forward
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_DCFAIL)
        self.rpf_intf = None
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route_ir()

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_nonerpf_dcfail_fec(self):
        #(*,g) none rpf, dc fail: Action: forward
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_FEC)
        self.rpf_intf = None
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_nonerpf_dcfail_fec_ir(self):
        #(*,g) none rpf, dc fail: Action: forward
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_FEC)
        self.rpf_intf = None
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route_ir()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_nonerpf_dcpass(self):
        #(*,g) none rpf, dc pass: Action: snoop and forward
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = None
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route(extra_packet=snoop_packet)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_nonerpf_dcpass_ir(self):
        #(*,g) none rpf, dc pass: Action: snoop and forward
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = None
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route_ir(extra_packet=snoop_packet)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    def test_route_rpffail_dcfail(self):
        #(*,g) hit rpf fail, dc fail: Action: punt
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_DCFAIL)
        self.construct_punt_packet(trap_code=sdk.LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL)
        punt_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_PUNT,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_l3_ac1.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False  # TODO: Fix in NPL required
        self.do_test_route(extra_packet=punt_packet)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_rpffail_dcfail_ir(self):
        #(*,g) hit rpf fail, dc fail: Action: punt
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_DCFAIL)
        self.construct_punt_packet(trap_code=sdk.LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL)
        punt_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_PUNT,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_l3_ac1.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False  # TODO: Fix in NPL required
        self.do_test_route_ir(extra_packet=punt_packet)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    def test_route_rpffail_dcfail_fec(self):
        #(*,g) hit rpf fail, dc fail: Action: punt
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_FEC)
        self.construct_punt_packet(trap_code=sdk.LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL)
        punt_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_PUNT,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_l3_ac1.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False  # TODO: Fix in NPL required
        self.do_test_route(extra_packet=punt_packet)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_rpffail_dcfail_fec_ir(self):
        #(*,g) hit rpf fail, dc fail: Action: punt
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_FEC)
        self.construct_punt_packet(trap_code=sdk.LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL)
        punt_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_PUNT,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_l3_ac1.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False  # TODO: Fix in NPL required
        self.do_test_route_ir(extra_packet=punt_packet)

    def test_route_rpffail_dcpass(self):
        #(*,g) hit rpf fail, dc pass: Action: punt
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP)
        self.construct_punt_packet(trap_code=sdk.LA_EVENT_L3_IP_MC_PUNT_DC_PASS)
        punt_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_PUNT,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_l3_ac1.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False  # TODO: Fix in NPL required
        self.do_test_route(extra_packet=punt_packet)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_rpffail_dcpass_ir(self):
        #(*,g) hit rpf fail, dc pass: Action: punt
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP)
        self.construct_punt_packet(trap_code=sdk.LA_EVENT_L3_IP_MC_PUNT_DC_PASS)
        punt_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_PUNT,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_l3_ac1.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False  # TODO: Fix in NPL required
        self.do_test_route_ir(extra_packet=punt_packet)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_rpfpass_dcfail(self):
        #(*,g) hit rpf pass, dc fail: Action: forward
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_DCFAIL)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_rpfpass_dcfail_ir(self):
        #(*,g) hit rpf pass, dc fail: Action: forward
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_DCFAIL)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route_ir()

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_rpfpass_dcfail_fec(self):
        #(*,g) hit rpf pass, dc fail: Action: forward
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_FEC)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_rpfpass_dcfail_fec_ir(self):
        #(*,g) hit rpf pass, dc fail: Action: forward
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_FEC)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route_ir()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_rpfpass_dcpass(self):
        #(*,g) hit rpf pass, dc pass: Action: snoop and forward
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route(extra_packet=snoop_packet)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_rpfpass_dcpass_ir(self):
        #(*,g) hit rpf pass, dc pass: Action: snoop and forward
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route_ir(extra_packet=snoop_packet)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_empty_mcg(self):
        # Even MC packets that do not belong to any MC group need to be able to be mirrored before being dropped
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.is_mcast_route_hit = True
        self.do_test_route_to_empty_mcg(extra_packet=snoop_packet)

    # Tx and Rx port disable cases for Multicast.
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_gmiss_dcfail_disable_rx(self):
        #(*,g) miss, dc fail: Action: drop
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR_MISS, ipv4_mc.SIP_DCFAIL)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False
        self.do_test_route(disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_gmiss_dcfail_disable_tx(self):
        #(*,g) miss, dc fail: Action: drop
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR_MISS, ipv4_mc.SIP_DCFAIL)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False
        self.do_test_route(disable_tx=True)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_gmiss_dcfail_fec_disable_rx(self):
        #(*,g) miss, dc fail: Action: drop
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR_MISS, ipv4_mc.SIP_FEC)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False
        self.do_test_route(disable_rx=True)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_gmiss_dcfail_fec_disable_tx(self):
        #(*,g) miss, dc fail: Action: drop
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR_MISS, ipv4_mc.SIP_FEC)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False
        self.do_test_route(disable_tx=True)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_nonerpf_dcfail_disable_rx(self):
        #(*,g) none rpf, dc fail: Action: forward
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_DCFAIL)
        self.rpf_intf = None
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route(disable_rx=True)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_nonerpf_dcfail_disable_tx(self):
        #(*,g) none rpf, dc fail: Action: forward
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_DCFAIL)
        self.rpf_intf = None
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route(disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_gmiss_dcpass_disable_rx(self):
        #(*,g) miss, dc pass: Action: punt
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR_MISS, ipv4_mc.SIP)
        self.construct_punt_packet(trap_code=sdk.LA_EVENT_L3_IP_MC_PUNT_DC_PASS)
        punt_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_PUNT,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False
        self.do_test_route(extra_packet=punt_packet, disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_gmiss_dcpass_disable_tx(self):
        #(*,g) miss, dc pass: Action: punt
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR_MISS, ipv4_mc.SIP)
        self.construct_punt_packet(trap_code=sdk.LA_EVENT_L3_IP_MC_PUNT_DC_PASS)
        punt_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_PUNT,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False
        self.do_test_route(extra_packet=punt_packet, disable_tx=True)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_nonerpf_dcfail_fec_disable_rx(self):
        #(*,g) none rpf, dc fail: Action: forward
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_FEC)
        self.rpf_intf = None
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route(disable_rx=True)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_nonerpf_dcfail_fec_disable_tx(self):
        #(*,g) none rpf, dc fail: Action: forward
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_FEC)
        self.rpf_intf = None
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route(disable_tx=True)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_nonerpf_dcpass_disable_rx(self):
        #(*,g) none rpf, dc pass: Action: snoop and forward
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = None
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route(extra_packet=snoop_packet, disable_rx=True)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_nonerpf_dcpass_disable_tx(self):
        #(*,g) none rpf, dc pass: Action: snoop and forward
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = None
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route(extra_packet=snoop_packet, disable_tx=True)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_rpffail_dcfail_disable_rx(self):
        #(*,g) hit rpf fail, dc fail: Action: punt
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_DCFAIL)
        self.construct_punt_packet(trap_code=sdk.LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL)
        punt_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_PUNT,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_l3_ac1.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False  # TODO: Fix in NPL required
        self.do_test_route(extra_packet=punt_packet, disable_rx=True)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_rpffail_dcfail_disable_tx(self):
        #(*,g) hit rpf fail, dc fail: Action: punt
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_DCFAIL)
        self.construct_punt_packet(trap_code=sdk.LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL)
        punt_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_PUNT,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_l3_ac1.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False  # TODO: Fix in NPL required
        self.do_test_route(extra_packet=punt_packet, disable_tx=True)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_rpffail_dcfail_fec_disable_rx(self):
        #(*,g) hit rpf fail, dc fail: Action: punt
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_FEC)
        self.construct_punt_packet(trap_code=sdk.LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL)
        punt_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_PUNT,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_l3_ac1.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False  # TODO: Fix in NPL required
        self.do_test_route(extra_packet=punt_packet, disable_rx=True)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_rpffail_dcfail_fec_disable_tx(self):
        #(*,g) hit rpf fail, dc fail: Action: punt
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_FEC)
        self.construct_punt_packet(trap_code=sdk.LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL)
        punt_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_PUNT,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_l3_ac1.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False  # TODO: Fix in NPL required
        self.do_test_route(extra_packet=punt_packet, disable_tx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_rpffail_dcpass_disable_rx(self):
        #(*,g) hit rpf fail, dc pass: Action: punt
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP)
        self.construct_punt_packet(trap_code=sdk.LA_EVENT_L3_IP_MC_PUNT_DC_PASS)
        punt_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_PUNT,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_l3_ac1.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False  # TODO: Fix in NPL required
        self.do_test_route(extra_packet=punt_packet, disable_rx=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_rpffail_dcpass_disable_tx(self):
        #(*,g) hit rpf fail, dc pass: Action: punt
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP)
        self.construct_punt_packet(trap_code=sdk.LA_EVENT_L3_IP_MC_PUNT_DC_PASS)
        punt_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_PUNT,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_l3_ac1.hld_obj
        self.trap = True
        self.is_mcast_route_hit = False  # TODO: Fix in NPL required
        self.do_test_route(extra_packet=punt_packet, disable_tx=True)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_rpfpass_dcfail_disable_rx(self):
        #(*,g) hit rpf pass, dc fail: Action: forward
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_DCFAIL)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route(disable_rx=True)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_rpfpass_dcfail_disable_tx(self):
        #(*,g) hit rpf pass, dc fail: Action: forward
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_DCFAIL)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route(disable_tx=True)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_rpfpass_dcfail_fec_disable_rx(self):
        #(*,g) hit rpf pass, dc fail: Action: forward
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_FEC)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route(disable_rx=True)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_rpfpass_dcfail_fec_disable_tx(self):
        #(*,g) hit rpf pass, dc fail: Action: forward
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_FEC)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route(disable_tx=True)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_rpfpass_dcpass_disable_rx(self):
        #(*,g) hit rpf pass, dc pass: Action: snoop and forward
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route(extra_packet=snoop_packet, disable_rx=True)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_rpfpass_dcpass_disable_tx(self):
        #(*,g) hit rpf pass, dc pass: Action: snoop and forward
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_l3_ac.hld_obj
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route(extra_packet=snoop_packet, disable_tx=True)

    def get_tx_l2_port(self):
        return None

    def get_tx_l2_port_def(self):
        return None

    def get_tx_sys_port(self):
        return self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj

    def get_tx_sys_port_def(self):
        return self.topology.tx_l3_ac_eth_port_def.sys_port.hld_obj


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv4_l3_ac_s_g_mc(ipv4_s_g_mc):
    INPUT_PACKET_BASE = \
        Ether(dst=ipv4_mc.get_mc_sa_addr_str(ipv4_s_g_mc.MC_GROUP_ADDR), src=mc_base.SA.addr_str, type=Ethertype.QinQ.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        IP(src=ipv4_mc.SIP.addr_str, dst=ipv4_s_g_mc.MC_GROUP_ADDR.addr_str, ttl=mc_base.TTL) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_BASE = Ether(dst=ipv4_mc.get_mc_sa_addr_str(ipv4_s_g_mc.MC_GROUP_ADDR),
                                        src=T.TX_L3_AC_REG_MAC.addr_str) / IP(src=ipv4_mc.SIP.addr_str,
                                                                              dst=ipv4_s_g_mc.MC_GROUP_ADDR.addr_str,
                                                                              ttl=mc_base.TTL - 1) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_DEF_BASE = \
        Ether(dst=ipv4_mc.get_mc_sa_addr_str(ipv4_s_g_mc.MC_GROUP_ADDR), src=T.TX_L3_AC_DEF_MAC.addr_str) / \
        IP(src=ipv4_mc.SIP.addr_str, dst=ipv4_s_g_mc.MC_GROUP_ADDR.addr_str, ttl=mc_base.TTL - 1) / TCP() / Raw(load=RAW_PAYLOAD)

    INPUT_PACKET, EXPECTED_OUTPUT_PACKET = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)
    __, EXPECTED_OUTPUT_PACKET_DEF = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_DEF_BASE)

    EXPECTED_OUTPUT_PACKET_PUNT = \
        Ether(dst=mc_base.HOST_MAC_ADDR, src=mc_base.PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
        Dot1Q(prio=0, id=0, vlan=mc_base.PUNT_VLAN, type=Ethertype.Punt.value) / \
        Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
             fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4,
             next_header_offset=len(Ether()) + 2 * len(Dot1Q()),
             source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
             code=sdk.LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL,
             source_sp=T.RX_SYS_PORT_GID,
             destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
             source_lp=T.RX_L3_AC_GID,
             destination_lp=sdk.LA_EVENT_L3_IP_MC_PUNT_RPF_FAIL,
             relay_id=T.VRF_GID,
             lpts_flow_type=0) / \
        INPUT_PACKET

    l3_port_impl_class = T.ip_l3_ac_base
    output_serdes = T.FIRST_SERDES_L3
    svi = False

    def setUp(self):
        super().setUp()
        mc_base.rechoose_odd_inject_slice(self.device)

    #(s,g) hit, none rpf Action: Forward
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_sg_nonerpf(self):
        self.trap = False
        self.is_mcast_route_hit = True
        self.rpf_intf = None
        self.do_test_route()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    #(s,g) hit, none rpf Action: Forward
    def test_route_sg_nonerpf_ir(self):
        self.trap = False
        self.is_mcast_route_hit = True
        self.rpf_intf = None
        self.do_test_route_ir()

    #(s,g) hit, rpf-fail Action: Drop (punt_on_rpf_fail set to false)
    def test_route_sg_rpffail(self):
        self.trap = True
        self.is_mcast_route_hit = False  # TODO: Fix in NPL required, should be True
        self.rpf_intf = self.topology.rx_l3_ac1.hld_obj
        self.do_test_route()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    #(s,g) hit, rpf-fail Action: Drop (punt_on_rpf_fail set to false)
    def test_route_sg_rpffail_ir(self):
        self.trap = True
        self.is_mcast_route_hit = False  # TODO: Fix in NPL required, should be True
        self.rpf_intf = self.topology.rx_l3_ac1.hld_obj
        self.do_test_route_ir()

    #(s,g) hit, rpf-fail Action: Punt (punt_on_rpf_fail set to true)
    def test_route_sg_rpffail_punt(self):
        self.trap = True
        self.is_mcast_route_hit = False  # TODO: Fix in NPL required, should be True
        self.rpf_intf = self.topology.rx_l3_ac1.hld_obj
        punt_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_PUNT,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.do_test_route(extra_packet=punt_packet, punt_on_rpf_fail=True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    #(s,g) hit, rpf-fail Action: Punt (punt_on_rpf_fail set to true)
    def test_route_sg_rpffail_punt_ir(self):
        self.trap = True
        self.is_mcast_route_hit = False  # TODO: Fix in NPL required, should be True
        self.rpf_intf = self.topology.rx_l3_ac1.hld_obj
        punt_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_PUNT,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.do_test_route_ir(extra_packet=punt_packet, punt_on_rpf_fail=True)

    #(s,g) hit, rpf-pass Action: Forward
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_sg_rpfpass(self):
        self.trap = False
        self.is_mcast_route_hit = True
        self.rpf_intf = rpf = self.topology.rx_l3_ac.hld_obj
        self.do_test_route()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    #(s,g) hit, rpf-pass Action: Forward
    def test_route_sg_rpfpass_ir(self):
        self.trap = False
        self.is_mcast_route_hit = True
        self.rpf_intf = rpf = self.topology.rx_l3_ac.hld_obj
        self.do_test_route_ir()

    #(s,g) hit, rpf-pass Action: Forward (punt_on_rpf_fail set to true)
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_s_g_rpf_pass_punt_on_rpf_fail_true(self):
        self.trap = False
        self.is_mcast_route_hit = True
        self.rpf_intf = rpf = self.topology.rx_l3_ac.hld_obj
        self.do_test_route(punt_on_rpf_fail=True)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    #(s,g) hit, rpf-pass Action: Forward (punt_on_rpf_fail set to true)
    def test_route_s_g_rpf_pass_punt_on_rpf_fail_true_ir(self):
        self.trap = False
        self.is_mcast_route_hit = True
        self.rpf_intf = rpf = self.topology.rx_l3_ac.hld_obj
        self.do_test_route_ir(punt_on_rpf_fail=True)

    def get_tx_l2_port(self):
        return None

    def get_tx_l2_port_def(self):
        return None

    def get_tx_sys_port(self):
        return self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj

    def get_tx_sys_port_def(self):
        return self.topology.tx_l3_ac_eth_port_def.sys_port.hld_obj


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv4_l3_ac_unmatched_mc(unmatched_mc_ipv4_test, unmatched_mc_l3_ac_test, unmatched_mc_base):

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
class ipv4_svi_egress_member_punt(egress_member_punt_ipv4_test, egress_member_punt_svi_test, egress_member_punt_base):
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_member_punt(self):
        self.do_test_egress_member_punt()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_member_punt_member_remove(self):
        self.do_test_egress_member_punt_member_remove()

    def test_egress_member_punt_member_get(self):
        self.do_test_egress_member_punt_member_get()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv4_svi_g_mc_mtu(ipv4_g_mc):
    RX_SVI_GID = 0x2a

    INPUT_PACKET_BASE = \
        Ether(dst=ipv4_mc.get_mc_sa_addr_str(ipv4_g_mc.MC_GROUP_ADDR), src=mc_base.SA.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
        IP(src=ipv4_mc.SIP.addr_str, dst=ipv4_g_mc.MC_GROUP_ADDR.addr_str, ttl=mc_base.TTL) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_BASE = Ether(dst=ipv4_mc.get_mc_sa_addr_str(ipv4_g_mc.MC_GROUP_ADDR),
                                        src=T.TX_SVI_MAC.addr_str) / IP(src=ipv4_mc.SIP.addr_str,
                                                                        dst=ipv4_g_mc.MC_GROUP_ADDR.addr_str,
                                                                        ttl=mc_base.TTL - 1) / TCP() / Raw(load=RAW_PAYLOAD)

    INPUT_PACKET, EXPECTED_OUTPUT_PACKET = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)
    EXPECTED_OUTPUT_PACKET_DEF = EXPECTED_OUTPUT_PACKET

    l3_port_impl_class = T.ip_svi_base
    output_serdes = T.FIRST_SERDES_SVI

    def setUp(self):
        ipv4_g_mc.setUp(self)
        self.topology.rx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)

    def test_route_mtu(self):
        self.do_test_route_mtu()

    def get_tx_l2_port(self):
        return self.topology.tx_l2_ac_port_reg.hld_obj

    def get_tx_l2_port_def(self):
        return self.topology.tx_l2_ac_port_def.hld_obj

    def get_tx_sys_port(self):
        return self.topology.tx_svi_eth_port_reg.sys_port.hld_obj

    def get_tx_sys_port_def(self):
        return self.topology.tx_svi_eth_port_def.sys_port.hld_obj


@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
@unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
class ipv4_svi_s_g_mc(ipv4_s_g_mc):
    RX_SVI_GID = 0x2a

    INPUT_PACKET_BASE = \
        Ether(dst=ipv4_mc.get_mc_sa_addr_str(ipv4_s_g_mc.MC_GROUP_ADDR), src=mc_base.SA.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
        IP(src=ipv4_mc.SIP.addr_str, dst=ipv4_s_g_mc.MC_GROUP_ADDR.addr_str, ttl=mc_base.TTL) / TCP() / Raw(load=RAW_PAYLOAD)

    EXPECTED_OUTPUT_PACKET_BASE = Ether(dst=ipv4_mc.get_mc_sa_addr_str(ipv4_s_g_mc.MC_GROUP_ADDR),
                                        src=T.TX_SVI_MAC.addr_str) / IP(src=ipv4_mc.SIP.addr_str,
                                                                        dst=ipv4_s_g_mc.MC_GROUP_ADDR.addr_str,
                                                                        ttl=mc_base.TTL - 1) / TCP() / Raw(load=RAW_PAYLOAD)

    INPUT_PACKET, EXPECTED_OUTPUT_PACKET = pad_input_and_output_packets(INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)
    EXPECTED_OUTPUT_PACKET_DEF = EXPECTED_OUTPUT_PACKET

    EXPECTED_OUTPUT_PACKET_SNOOP = \
        Ether(dst=mc_base.HOST_MAC_ADDR, src=mc_base.PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
        Dot1Q(prio=0, id=0, vlan=mc_base.MIRROR_VLAN, type=Ethertype.Punt.value) / \
        Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
             fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4_COLLAPSED_MC,
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

    l3_port_impl_class = T.ip_svi_base
    output_serdes = T.FIRST_SERDES_SVI
    ip_impl = ip_test_base.ipv4_test_base()
    svi = True

    def setUp(self):
        # MATILDA_SAVE -- need review
        if (mc_base.INJECT_SLICE not in self.device.get_used_slices()) or \
                (mc_base.BRIDGE_SLICE not in self.device.get_used_slices()):
            self.skipTest("Skip test when in mathilda mode.")
            return
            # self.PUNT_SLICE=T.choose_active_slices(self.device, self.PUNT_SLICE, [4,2], 2)
        mc_base.rechoose_odd_inject_slice(self.device)

        ipv4_s_g_mc.setUp(self)
        self.topology.rx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)

        # Create port in rx_svi to receive bridge copies
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

        self.eth_port2 = T.ethernet_port(
            self,
            self.device,
            mc_base.BRIDGE_SLICE,
            mc_base.BRIDGE_IFG,
            mc_base.BRIDGE_SYS_PORT2_GID,
            mc_base.BRIDGE_SERDES2,
            mc_base.BRIDGE_SERDES2 + 1)
        self.ac_port2 = T.l2_ac_port(self, self.device, mc_base.BRIDGE_AC_PORT2_GID, None, self.topology.rx_switch,
                                     self.eth_port2, T.RX_MAC, T.RX_L2_AC_PORT_VID1, T.RX_L2_AC_PORT_VID2)
        self.mc_group.add(self.l3_port_impl.rx_port.hld_obj, self.ac_port2.hld_obj, self.eth_port2.sys_port.hld_obj)

        self.rxsw_floodset = self.device.create_l2_multicast_group(mc_base.MC_GROUP_GID + 5, sdk.la_replication_paradigm_e_EGRESS)
        self.rxsw_floodset.add(self.ac_port1.hld_obj, self.eth_port1.sys_port.hld_obj)
        self.rxsw_floodset.add(self.ac_port2.hld_obj, self.eth_port2.sys_port.hld_obj)
        self.topology.rx_switch.hld_obj.set_flood_destination(self.rxsw_floodset)

        self.rxsw_mrouter = self.device.create_l2_multicast_group(mc_base.MC_GROUP_GID + 6, sdk.la_replication_paradigm_e_EGRESS)
        self.rxsw_mrouter.add(self.ac_port2.hld_obj, self.eth_port2.sys_port.hld_obj)

        self.topology.rx_switch.hld_obj.set_ipv4_multicast_enabled(True)
        self.rxsw_snoop = self.device.create_l2_multicast_group(mc_base.MC_GROUP_GID + 7, sdk.la_replication_paradigm_e_EGRESS)
        self.rxsw_snoop.add(self.ac_port1.hld_obj, self.eth_port1.sys_port.hld_obj)
        self.rxsw_snoop.add(self.ac_port2.hld_obj, self.eth_port2.sys_port.hld_obj)

    #(s,g)hit, none rpf, Action: Forward and bridge
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_sg_nonerpf(self):
        self.rpf_intf = None
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route()

    #(s,g)hit, none rpf, Action: Forward and bridge
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_sg_nonerpf_ir(self):
        self.rpf_intf = None
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route_ir()

    #(s,g)hit, rpf-fail, Action: Bridge (punt_on_rpf_fail set as false)
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_sg_rpffail(self):
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port1.hld_obj)
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port2.hld_obj)
        self.rpffail = True
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_svi1.hld_obj
        self.trap = True
        self.is_mcast_route_hit = True
        self.do_test_route()

    #(s,g)hit, rpf-fail, Action: Bridge (punt_on_rpf_fail set as false)
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_sg_rpffail_ir(self):
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port1.hld_obj)
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port2.hld_obj)
        self.rpffail = True
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_svi1.hld_obj
        self.trap = True
        self.is_mcast_route_hit = True
        self.do_test_route_ir()

    #(s,g)hit, rpf-fail, Action: Snoop and bridge (punt_on_rpf_fail set as true)
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_sg_rpffail_punt(self):
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port1.hld_obj)
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port2.hld_obj)
        self.rpffail = True
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_svi1.hld_obj
        self.trap = True
        self.is_mcast_route_hit = True
        self.do_test_route(extra_packet=snoop_packet, punt_on_rpf_fail=True)

    #(s,g)hit, rpf-fail, Action: Snoop and bridge (punt_on_rpf_fail set as true)
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_sg_rpffail_punt_ir(self):
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port1.hld_obj)
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port2.hld_obj)
        self.rpffail = True
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_svi1.hld_obj
        self.trap = True
        self.is_mcast_route_hit = True
        self.do_test_route_ir(extra_packet=snoop_packet, punt_on_rpf_fail=True)

    #(s,g)hit, rpf-pass, Action: Forward and bridge
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_sg_rpfpass(self):
        self.rpf_intf = self.topology.rx_svi.hld_obj
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route()

    #(s,g)hit, rpf-pass, Action: Forward and bridge
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_sg_rpfpass_ir(self):
        self.rpf_intf = self.topology.rx_svi.hld_obj
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route_ir()

    #(s,g)hit, rpf-pass, Action: Forward and bridge (punt_on_rpf_fail set as true)
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_s_g_rpfpass_punt_on_rpf_fail_true(self):
        self.rpf_intf = self.topology.rx_svi.hld_obj
        self.trap = False
        self.is_mcast_route_hit = True
        self.do_test_route(punt_on_rpf_fail=True)

    #(s,g)hit, rpf-pass, Action: Forward and bridge (punt_on_rpf_fail set as true)
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_s_g_rpfpass_punt_on_rpf_fail_true_ir(self):
        self.rpf_intf = self.topology.rx_svi.hld_obj
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


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv4_svi_g_mc(ipv4_g_mc):
    RX_SVI_GID = 0x2a

    l3_port_impl_class = T.ip_svi_base
    output_serdes = T.FIRST_SERDES_SVI
    ip_impl = ip_test_base.ipv4_test_base()
    svi = True

    def setUp(self):
        # MATILDA_SAVE -- need review
        if (mc_base.INJECT_SLICE not in self.device.get_used_slices()) or \
                (mc_base.BRIDGE_SLICE not in self.device.get_used_slices()):
            self.skipTest("Skip test when in mathilda mode.")
            return
            # self.PUNT_SLICE=T.choose_active_slices(self.device, self.PUNT_SLICE, [4,2])
        mc_base.rechoose_odd_inject_slice(self.device)

        ipv4_g_mc.setUp(self)

        # Init snoops and Traps
        pi_port = T.punt_inject_port(self, self.device, mc_base.INJECT_SLICE, mc_base.INJECT_IFG, mc_base.INJECT_SP_GID,
                                     mc_base.INJECT_PIF_FIRST, mc_base.PUNT_INJECT_PORT_MAC_ADDR)
        punt_dest = T.create_l2_punt_destination(self, self.device, T.L2_PUNT_DESTINATION2_GID,
                                                 pi_port, mc_base.HOST_MAC_ADDR, mc_base.PUNT_VLAN)
        mirror_cmd = T.create_l2_mirror_command(self.device, mc_base.MIRROR_CMD_INGRESS_GID, pi_port,
                                                mc_base.HOST_MAC_ADDR, mc_base.MIRROR_VLAN)
        mc_base.initSnoopsAndTraps(self.device, punt_dest, mirror_cmd)
        self.topology.rx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)

        # Add subnet for DC pass
        subnet = self.ip_impl.build_prefix(ipv4_mc.SIP, length=16)
        self.ip_impl.add_subnet(self.topology.rx_l3_ac, subnet)

        # Add route with fec for DC fail
        nh = T.next_hop(self, self.device, mc_base.NH_GID, mc_base.NH_MAC, self.topology.rx_l3_ac)
        fec = T.fec(self, self.device, nh)
        prefix = self.ip_impl.build_prefix(ipv4_mc.SIP_FEC, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, fec, mc_base.PRIVATE_DATA)

        # Create port in rx_svi to receive bridge copies
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

        self.eth_port2 = T.ethernet_port(
            self,
            self.device,
            mc_base.BRIDGE_SLICE,
            mc_base.BRIDGE_IFG,
            mc_base.BRIDGE_SYS_PORT2_GID,
            mc_base.BRIDGE_SERDES2,
            mc_base.BRIDGE_SERDES2 + 1)
        self.ac_port2 = T.l2_ac_port(self, self.device, mc_base.BRIDGE_AC_PORT2_GID, None, self.topology.rx_switch,
                                     self.eth_port2, T.RX_MAC, T.RX_L2_AC_PORT_VID1, T.RX_L2_AC_PORT_VID2)
        self.mc_group.add(self.l3_port_impl.rx_port.hld_obj, self.ac_port2.hld_obj, self.eth_port2.sys_port.hld_obj)

        self.rxsw_floodset = self.device.create_l2_multicast_group(mc_base.MC_GROUP_GID + 5, sdk.la_replication_paradigm_e_EGRESS)
        self.rxsw_floodset.add(self.ac_port1.hld_obj, self.eth_port1.sys_port.hld_obj)
        self.rxsw_floodset.add(self.ac_port2.hld_obj, self.eth_port2.sys_port.hld_obj)
        self.topology.rx_switch.hld_obj.set_flood_destination(self.rxsw_floodset)

        self.rxsw_mrouter = self.device.create_l2_multicast_group(mc_base.MC_GROUP_GID + 6, sdk.la_replication_paradigm_e_EGRESS)
        self.rxsw_mrouter.add(self.ac_port2.hld_obj, self.eth_port2.sys_port.hld_obj)

        self.topology.rx_switch.hld_obj.set_ipv4_multicast_enabled(True)
        self.rxsw_snoop = self.device.create_l2_multicast_group(mc_base.MC_GROUP_GID + 7, sdk.la_replication_paradigm_e_EGRESS)
        self.rxsw_snoop.add(self.ac_port1.hld_obj, self.eth_port1.sys_port.hld_obj)
        self.rxsw_snoop.add(self.ac_port2.hld_obj, self.eth_port2.sys_port.hld_obj)

    def construct_packet(self, mc_mac, source_ip):
        INPUT_PACKET_BASE = \
            Ether(dst=ipv4_mc.get_mc_sa_addr_str(mc_mac), src=mc_base.SA.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            IP(src=source_ip.addr_str, dst=mc_mac.addr_str, ttl=mc_base.TTL) / TCP() / Raw(load=RAW_PAYLOAD)

        EXPECTED_OUTPUT_PACKET_BASE = \
            Ether(dst=ipv4_mc.get_mc_sa_addr_str(mc_mac), src=T.TX_SVI_MAC.addr_str) / \
            IP(src=source_ip.addr_str, dst=mc_mac.addr_str, ttl=mc_base.TTL - 1) / TCP() / Raw(load=RAW_PAYLOAD)

        self.INPUT_PACKET, self.EXPECTED_OUTPUT_PACKET = pad_input_and_output_packets(
            INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)
        self.EXPECTED_OUTPUT_PACKET_DEF = self.EXPECTED_OUTPUT_PACKET

    def construct_snoop_packet(self):
        self.EXPECTED_OUTPUT_PACKET_SNOOP = \
            Ether(dst=mc_base.HOST_MAC_ADDR, src=mc_base.PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
            Dot1Q(prio=0, id=0, vlan=mc_base.MIRROR_VLAN, type=Ethertype.Punt.value) / \
            Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                 fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_IPV4_COLLAPSED_MC,
                 next_header_offset=0,
                 source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR,
                 code=mc_base.MIRROR_CMD_INGRESS_GID,
                 source_sp=T.RX_SYS_PORT_GID,
                 destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                 source_lp=T.RX_SVI_GID,
                 destination_lp=0,
                 relay_id=T.VRF_GID,
                 lpts_flow_type=0) / \
            self.INPUT_PACKET

    # For all tests:
    # 1. construct input and expected output packets (with required mc_mac and sip)
    # 2. construct any expected cpu packets (trap or snoop packets)
    # 3. set the rpf value (for rpf pass or rpf fail)
    # 4. set trap boolean, if set to True, it is a trap otherwise snoop
    #    this value is used in base class to construct the expected_packets list
    # 5. set pcount - packet count
    #    this value is used in base class to verify the counters
    # 6. set svi to True, when incoming packet is on svi, packet may be bridged in
    #    some test cases. This value is used in base class to verify if the
    #    expected_packets list should include bridged copies or not
    # The original cases with 'none' rpf are also maintained. They are considered
    # rpf pass cases with directly connected check pass or fail.
    #
    # For (*,g) miss cases, different mc mac is used.
    # For DC fail cases (directly connected check fail), different source ip is used.
    # For RPF fail cases, rx_svi1 is used.

    #(*,g) miss cases are yet to be done. Commenting these test cases for now, until,
    # NPL changes are ready

    @unittest.skipIf(True, "Awaiting NPL support for this test")
    #(*,g) miss, dc fail Action: snoop and bridge
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    def test_route_gmiss_dcfail(self):
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR_MISS, ipv4_mc.SIP_DCFAIL)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_svi.hld_obj
        self.is_mcast_route_hit = False
        self.trap = True
        self.do_test_route(extra_packet=snoop_packet)

    @unittest.skipIf(True, "Awaiting NPL support for this test")
    #(*,g) miss, dc fail Action: snoop and bridge
    def test_route_gmiss_dcfail_ir(self):
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR_MISS, ipv4_mc.SIP_DCFAIL)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_svi.hld_obj
        self.is_mcast_route_hit = False
        self.trap = True
        self.do_test_route_ir(extra_packet=snoop_packet)

    @unittest.skipIf(True, "Awaiting NPL support for this test")
    #(*,g) miss, dc fail Action: snoop and bridge
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_gmiss_dcfail_fec(self):
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR_MISS, ipv4_mc.SIP_FEC)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_svi.hld_obj
        self.is_mcast_route_hit = False
        self.trap = True
        self.do_test_route(extra_packet=snoop_packet)

    @unittest.skipIf(True, "Awaiting NPL support for this test")
    #(*,g) miss, dc fail Action: snoop and bridge
    def test_route_gmiss_dcfail_fec_ir(self):
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR_MISS, ipv4_mc.SIP_FEC)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_svi.hld_obj
        self.is_mcast_route_hit = False
        self.trap = True
        self.do_test_route_ir(extra_packet=snoop_packet)

    @unittest.skipIf(True, "Awaiting NPL support for this test")
    #(*,g) miss, dc pass Action: snoop and bridge
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    def test_route_gmiss_dcpass(self):
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR_MISS, ipv4_mc.SIP)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_svi.hld_obj
        self.is_mcast_route_hit = False
        self.trap = True
        self.do_test_route(extra_packet=snoop_packet)

    @unittest.skipIf(True, "Awaiting NPL support for this test")
    #(*,g) miss, dc pass Action: snoop and bridge
    def test_route_gmiss_dcpass_ir(self):
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR_MISS, ipv4_mc.SIP)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_svi.hld_obj
        self.is_mcast_route_hit = False
        self.trap = True
        self.do_test_route_ir(extra_packet=snoop_packet)

    #(*,g) none rpf, dc fail Action: forward and bridge
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_nonerpf_dcfail(self):
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_DCFAIL)
        self.rpf_intf = None
        self.is_mcast_route_hit = True
        self.trap = False
        self.do_test_route()

    #(*,g) none rpf, dc fail Action: forward and bridge
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_nonerpf_dcfail_ir(self):
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_DCFAIL)
        self.rpf_intf = None
        self.is_mcast_route_hit = True
        self.trap = False
        self.do_test_route_ir()

    #(*,g) none rpf, dc fail Action: forward and bridge
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_nonerpf_dcfail_fec(self):
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_FEC)
        self.rpf_intf = None
        self.is_mcast_route_hit = True
        self.trap = False
        self.do_test_route()

    #(*,g) none rpf, dc fail Action: forward and bridge
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_nonerpf_dcfail_fec_ir(self):
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_FEC)
        self.rpf_intf = None
        self.is_mcast_route_hit = True
        self.trap = False
        self.do_test_route_ir()

    #(*,g) none rpf, dc pass Action: snoop, forward and bridge
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    def test_route_nonerpf_dcpass(self):
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = None
        self.is_mcast_route_hit = True
        self.trap = False
        self.do_test_route(extra_packet=snoop_packet)

    #(*,g) none rpf, dc pass Action: snoop, forward and bridge
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_nonerpf_dcpass_ir(self):
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = None
        self.is_mcast_route_hit = True
        self.trap = False
        self.do_test_route_ir(extra_packet=snoop_packet)

    #(*,g) hit rpf-fail, dc fail Action: snoop and bridge
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    def test_route_rpffail_dcfail(self):
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port1.hld_obj)
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port2.hld_obj)
        self.rpffail = True

        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_DCFAIL)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_svi1.hld_obj
        self.is_mcast_route_hit = True
        self.trap = True
        self.do_test_route(extra_packet=snoop_packet)

    #(*,g) hit rpf-fail, dc fail Action: snoop and bridge
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_rpffail_dcfail_ir(self):
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port1.hld_obj)
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port2.hld_obj)
        self.rpffail = True

        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_DCFAIL)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_svi1.hld_obj
        self.is_mcast_route_hit = True
        self.trap = True
        self.do_test_route_ir(extra_packet=snoop_packet)

    #(*,g) hit rpf-fail, dc fail Action: snoop and bridge
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_rpffail_dcfail_fec(self):
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port1.hld_obj)
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port2.hld_obj)
        self.rpffail = True

        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_FEC)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_svi1.hld_obj
        self.is_mcast_route_hit = True
        self.trap = True
        self.do_test_route(extra_packet=snoop_packet)

    #(*,g) hit rpf-fail, dc fail Action: snoop and bridge
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_rpffail_dcfail_fec_ir(self):
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port1.hld_obj)
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port2.hld_obj)
        self.rpffail = True

        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_FEC)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_svi1.hld_obj
        self.is_mcast_route_hit = True
        self.trap = True
        self.do_test_route_ir(extra_packet=snoop_packet)

    #(*,g) hit rpf-fail, dc pass Action: snoop and bridge
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_rpffail_dcpass(self):
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port1.hld_obj)
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port2.hld_obj)
        self.rpffail = True

        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_svi1.hld_obj
        self.is_mcast_route_hit = True
        self.trap = True
        self.do_test_route(extra_packet=snoop_packet)

    #(*,g) hit rpf-fail, dc pass Action: snoop and bridge
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_rpffail_dcpass_ir(self):
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port1.hld_obj)
        self.mc_group.remove(self.l3_port_impl.rx_port.hld_obj, self.ac_port2.hld_obj)
        self.rpffail = True

        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_svi1.hld_obj
        self.is_mcast_route_hit = True
        self.trap = True
        self.do_test_route_ir(extra_packet=snoop_packet)

    #(*,g) hit rpf-pass, dc fail Action: forward and bridge
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    def test_route_rpfpass_dcfail(self):
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_DCFAIL)
        self.rpf_intf = self.topology.rx_svi.hld_obj
        self.is_mcast_route_hit = True
        self.trap = False
        self.do_test_route()

    #(*,g) hit rpf-pass, dc fail Action: forward and bridge
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_rpfpass_dcfail_ir(self):
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_DCFAIL)
        self.rpf_intf = self.topology.rx_svi.hld_obj
        self.is_mcast_route_hit = True
        self.trap = False
        self.do_test_route_ir()

    #(*,g) hit rpf-pass, dc fail Action: forward and bridge
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_rpfpass_dcfail_fec(self):
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_FEC)
        self.rpf_intf = self.topology.rx_svi.hld_obj
        self.is_mcast_route_hit = True
        self.trap = False
        self.do_test_route()

    #(*,g) hit rpf-pass, dc fail Action: forward and bridge
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_rpfpass_dcfail_fec_ir(self):
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP_FEC)
        self.rpf_intf = self.topology.rx_svi.hld_obj
        self.is_mcast_route_hit = True
        self.trap = False
        self.do_test_route_ir()

    #(*,g) hit rpf-pass, dc pass Action: snoop, forward and bridge
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_rpfpass_dcpass(self):
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_svi.hld_obj
        self.is_mcast_route_hit = True
        self.trap = False
        self.do_test_route(extra_packet=snoop_packet)

    #(*,g) hit rpf-pass, dc pass Action: snoop, forward and bridge
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(), "Test is not yet enabled on Matilda")
    @unittest.skipIf(decor.is_hw_device(), "Test is not yet enabled on HW")
    def test_route_rpfpass_dcpass_ir(self):
        self.construct_packet(ipv4_g_mc.MC_GROUP_ADDR, ipv4_mc.SIP)
        self.construct_snoop_packet()
        snoop_packet = mc_base.extra_packet_struct(
            self.EXPECTED_OUTPUT_PACKET_SNOOP,
            mc_base.INJECT_SLICE,
            mc_base.INJECT_IFG,
            mc_base.INJECT_PIF_FIRST)
        self.rpf_intf = self.topology.rx_svi.hld_obj
        self.is_mcast_route_hit = True
        self.trap = False
        self.do_test_route_ir(extra_packet=snoop_packet)

    def get_tx_l2_port(self):
        return self.topology.tx_l2_ac_port_reg.hld_obj

    def get_tx_l2_port_def(self):
        return self.topology.tx_l2_ac_port_def.hld_obj

    def get_tx_sys_port(self):
        return self.topology.tx_svi_eth_port_reg.sys_port.hld_obj

    def get_tx_sys_port_def(self):
        return self.topology.tx_svi_eth_port_def.sys_port.hld_obj


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv4_svi_unmatched_mc(unmatched_mc_ipv4_test, unmatched_mc_svi_test, unmatched_mc_base):

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
class ipv4_mulitcast_disabled(sdk_multi_test_case_base):
    ttl = 127
    mc_group_addr = T.ipv4_addr('225.1.2.3')
    src_mac = T.mac_addr('be:ef:5d:35:7a:35')

    def setUp(self):
        super().setUp()
        mc_base.create_l2_ports(self)
        self.create_packets()

    def create_packets(self):
        INPUT_PACKET_BASE = \
            Ether(dst=ipv4_mc.get_mc_sa_addr_str(self.mc_group_addr), src=self.src_mac.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            IP(src=ipv4_mc.SIP.addr_str, dst=self.mc_group_addr.addr_str, ttl=self.ttl) / TCP() / Raw(load=RAW_PAYLOAD)

        EXPECTED_OUTPUT_PACKET_BASE = \
            Ether(dst=ipv4_mc.get_mc_sa_addr_str(self.mc_group_addr), src=self.src_mac.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            IP(src=ipv4_mc.SIP.addr_str, dst=self.mc_group_addr.addr_str, ttl=self.ttl) / TCP() / Raw(load=RAW_PAYLOAD)

        self.input_packet, self.output_packet = pad_input_and_output_packets(
            INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    def test_multicast_disabled(self):
        # IPV4_MC protocol is disabled on rx_svi, packet should be flooded on ingress vlan.
        ingress_packet = {'data': self.input_packet, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        egress_packets = []
        egress_packets.append({'data': self.output_packet, 'slice': T.RX_SLICE,
                               'ifg': T.RX_IFG, 'pif': mc_base.SERDES4})
        egress_packets.append({'data': self.output_packet, 'slice': T.RX_SLICE,
                               'ifg': T.RX_IFG, 'pif': mc_base.SERDES6})
        U.run_and_compare_list(self, self.device, ingress_packet, egress_packets)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
    def test_multicast_disabled_pkt_count(self):
        self.ingress_l2_counter_set_size = sdk.la_rate_limiters_packet_type_e_LAST
        self.ingress_l2_counter = self.device.create_counter(self.ingress_l2_counter_set_size)
        self.topology.rx_l2_ac_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.ingress_l2_counter)
        # IPV4_MC protocol is disabled on rx_svi, packet should be flooded on ingress vlan.
        ingress_packet = {'data': self.input_packet, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        egress_packets = []
        egress_packets.append({'data': self.output_packet, 'slice': T.RX_SLICE,
                               'ifg': T.RX_IFG, 'pif': mc_base.SERDES4})
        egress_packets.append({'data': self.output_packet, 'slice': T.RX_SLICE,
                               'ifg': T.RX_IFG, 'pif': mc_base.SERDES6})
        U.run_and_compare_list(self, self.device, ingress_packet, egress_packets)
        packets, byte_count = self.ingress_l2_counter.read(sdk.la_rate_limiters_packet_type_e_UNKNOWN_MC, True, True)
        self.assertEqual(packets, 1)
        assertPacketLengthIngress(self, self.input_packet, T.RX_SLICE, byte_count)


@unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fails P4")
@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
class ipv4_mulitcast_stp_block(sdk_multi_test_case_base):
    ttl = 127
    mc_group_addr = T.ipv4_addr('225.1.2.3')
    src_mac = T.mac_addr('be:ef:5d:35:7a:35')

    def setUp(self):
        super().setUp()
        self.create_packets()
        self.topology.rx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)
        self.topology.tx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)

        self.mc_group = self.device.create_ip_multicast_group(mc_base.MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)
        self.mc_group.add(
            self.topology.tx_svi.hld_obj,
            self.topology.tx_l2_ac_port_reg.hld_obj,
            self.topology.tx_svi_eth_port_reg.sys_port.hld_obj)
        self.mc_group.add(
            self.topology.tx_svi.hld_obj,
            self.topology.tx_l2_ac_port_def.hld_obj,
            self.topology.tx_svi_eth_port_def.sys_port.hld_obj)

    def create_packets(self):
        INPUT_PACKET_BASE = \
            Ether(dst=ipv4_mc.get_mc_sa_addr_str(self.mc_group_addr), src=self.src_mac.addr_str, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
            IP(src=ipv4_mc.SIP.addr_str, dst=self.mc_group_addr.addr_str, ttl=self.ttl) / TCP() / Raw(load=RAW_PAYLOAD)

        EXPECTED_OUTPUT_PACKET_BASE = \
            Ether(dst=ipv4_mc.get_mc_sa_addr_str(self.mc_group_addr), src=T.TX_SVI_MAC.addr_str) /\
            IP(src=ipv4_mc.SIP.addr_str, dst=self.mc_group_addr.addr_str, ttl=self.ttl - 1) / TCP() / Raw(load=RAW_PAYLOAD)

        self.INPUT_PACKET, self.EXPECTED_OUTPUT_PACKET = pad_input_and_output_packets(
            INPUT_PACKET_BASE, EXPECTED_OUTPUT_PACKET_BASE)

    def do_test_route(self):
        self.topology.vrf.hld_obj.add_ipv4_multicast_route(
            sdk.LA_IPV4_ANY_IP, self.mc_group_addr.hld_obj, self.mc_group, None, False, False, None)
        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                 'ifg': T.TX_IFG_REG, 'pif': T.FIRST_SERDES_SVI})
        expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_DEF,
                                 'ifg': T.TX_IFG_DEF, 'pif': T.FIRST_SERDES_SVI})

        U.run_and_compare_list(self, self.device, ingress_packet, expected_packets)

    def test_incoming_port_stp_block(self):
        self.do_test_route()
        self.topology.rx_l2_ac_port.hld_obj.set_stp_state(sdk.la_port_stp_state_e_BLOCKING)
        U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
def setUpModule():
    sdk_multi_test_case_base.initialize()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
def tearDownModule():
    sdk_multi_test_case_base.destroy()


if __name__ == '__main__':
    unittest.main()
