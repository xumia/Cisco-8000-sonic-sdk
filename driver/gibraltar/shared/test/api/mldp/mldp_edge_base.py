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


import sys
import unittest
from leaba import sdk
import ip_test_base
from scapy.all import *
from scapy.config import conf
from packet_test_utils import *

import sim_utils
import topology as T
from sdk_test_case_base import *
import mtu.mtu_test_utils as MTU
import ip_test_base
from mc_base import *
import enum

load_contrib('mpls')

PRIVATE_DATA = 0x1234567890abcdef


class node_type_e(enum.Enum):
    MLDP_HEAD_NODE = 1
    MLDP_BUD_NODE  = 2
    MLDP_TAIL_NODE = 3


class mldp_edge_base(sdk_test_case_base):

    RCY_SLICE = T.get_device_slice(1)

    def setUp(self):
        super().setUp()
        self.ip_impl = self.ip_impl_class()
        self.l3_port_impl = self.l3_port_impl_class(self.topology)

        # mcast group setup
        self.output_serdes = T.FIRST_SERDES_L3

        # Init snoops and Traps; common to head, bud and tail
        pi_port = T.punt_inject_port(self, self.device, mc_base.INJECT_SLICE, mc_base.INJECT_IFG, mc_base.INJECT_SP_GID,
                                     mc_base.INJECT_PIF_FIRST, mc_base.PUNT_INJECT_PORT_MAC_ADDR)

        self.punt_dest = T.create_l2_punt_destination(self, self.device, T.L2_PUNT_DESTINATION2_GID,
                                                      pi_port, mc_base.HOST_MAC_ADDR, mc_base.PUNT_VLAN)

        mirror_cmd = T.create_l2_mirror_command(self.device, mc_base.MIRROR_CMD_GID, pi_port,
                                                mc_base.HOST_MAC_ADDR, mc_base.MIRROR_VLAN)

        mc_base.initSnoopsAndTraps(self.device, self.punt_dest, mirror_cmd)

        self.topology.rx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)
        self.topology.rx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)
        self.topology.rx_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)
        self.topology.rx_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)

    def _test_get_info(self):
        lsr = self.device.get_lsr()

    def create_lpts(self):
        k = sdk.la_lpts_key()
        result = sdk.la_lpts_result()
        result.tc = 0
        result.dest = self.punt_dest
        result.counter_or_meter = T.create_meter_set(self, self.device, is_aggregate=True)
        result.meter = None

        if self.ipvx is 'v4':
            self.lpts_v4 = self.device.create_lpts(sdk.lpts_type_e_LPTS_TYPE_IPV4)
            self.assertNotEqual(self.lpts_v4, None)
            k.type = sdk.lpts_type_e_LPTS_TYPE_IPV4
            result.flow_type = mc_base.LPTS_FLOW_TYPE_V4
            result.punt_code = mc_base.LPTS_PUNT_CODE_V4
            self.lpts_v4.append(k, result)
        else:
            self.lpts_v6 = self.device.create_lpts(sdk.lpts_type_e_LPTS_TYPE_IPV6)
            self.assertNotEqual(self.lpts_v6, None)
            k.type = sdk.lpts_type_e_LPTS_TYPE_IPV6
            result.flow_type = mc_base.LPTS_FLOW_TYPE_V6
            result.punt_code = mc_base.LPTS_PUNT_CODE_V6
            self.lpts_v6.append(k, result)

    def _install_mldp_edge_node(self):
        lsr = self.device.get_lsr()

        if self.node_type is node_type_e.MLDP_TAIL_NODE:
            try:
                self.decap_obj = lsr.add_vpn_decap(
                    self.INPUT_LABEL_TAIL, self.topology.vrf.hld_obj, self.rpfid, False)
            except BaseException as STATUS:
                self.assertEqual(STATUS.args[0], self.exception)
                return

        elif self.node_type is node_type_e.MLDP_BUD_NODE:
            try:
                self.decap_obj = lsr.add_vpn_decap(
                    self.INPUT_LABEL_BUD, self.topology.vrf.hld_obj, self.rpfid, True)
            except BaseException as STATUS:
                self.assertEqual(STATUS.args[0], self.exception)
                return

            self.mpls_mc_group = self.device.create_mpls_multicast_group(
                self.MPLS_MC_GROUP_GID, sdk.la_replication_paradigm_e_EGRESS)

            lsr.add_route(self.INPUT_LABEL_BUD, self.mpls_mc_group, PRIVATE_DATA)

            self.l3_port_impl = T.ip_l3_ac_base(self.topology)
            lsp_labels = []
            lsp_labels.append(self.OUTPUT_LABEL)

            # MPLS NH for MPLS member
            self.prefix_object_mpls_l3_ac = self.device.create_prefix_object(
                self.DEF_PFX_OBJ_GID,
                self.l3_port_impl.reg_nh.hld_obj,
                sdk.la_prefix_object.prefix_type_e_NORMAL)
            self.prefix_object_mpls_l3_ac.set_nh_lsp_properties(
                self.l3_port_impl.reg_nh.hld_obj, lsp_labels, None, sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

            # add L3 AC to MPLS MC
            self.mpls_mc_group.add(self.prefix_object_mpls_l3_ac, self.get_tx_sys_port())

            # recycle port section
            self.recycle_eth_port = self.device.create_ethernet_port(
                self.topology.recycle_ports[self.RCY_SLICE].sys_port.hld_obj,
                sdk.la_ethernet_port.port_type_e_AC)
            self.recycle_eth_port.set_ac_profile(self.topology.ac_profile_def.hld_obj)

            # SLP so we terminate the MAC address and get service mapping
            self.recycle_l3_ac_port_termination = self.device.create_l3_ac_port(
                T.RX_L3_AC_GID + 0x201,
                self.recycle_eth_port,
                self.RECYCLE_VLAN,
                0,
                self.RECYCLE_PORT_MAC.hld_obj,
                self.topology.vrf.hld_obj,
                self.topology.ingress_qos_profile_def.hld_obj,
                self.topology.egress_qos_profile_def.hld_obj)

            # Set the vlan for the tx side for l3 ac
            tag = sdk.la_vlan_tag_t()
            tag.tpid = 0x8100
            tag.tci.fields.pcp = 0
            tag.tci.fields.dei = 0
            tag.tci.fields.vid = self.RECYCLE_VLAN

            self.recycle_l3_ac_port_termination.set_protocol_enabled(sdk.la_l3_protocol_e_MPLS, True)
            self.recycle_l3_ac_port_termination.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_MC, True)
            self.recycle_l3_ac_port_termination.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_MC, True)
            self.recycle_l3_ac_port_termination.set_egress_vlan_tag(tag, sdk.LA_VLAN_TAG_UNTAGGED)
            self.recycle_l3_ac_port_termination.set_mldp_bud_terminate_enabled(True)

            # add recycle AC to MPLS MC
            self.mpls_mc_group.add(self.recycle_l3_ac_port_termination)

        # head node
        else:
            pass  # implement later

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        # ipv4 route setup
        self.mc_group = self.device.create_ip_multicast_group(0x13, sdk.la_replication_paradigm_e_EGRESS)

        # mcast copies
        self.mc_group.add(self.l3_port_impl.tx_port.hld_obj, None, self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj)
        self.mc_group.add(self.topology.tx_l3_ac_def.hld_obj, None, self.topology.tx_l3_ac_eth_port_def.sys_port.hld_obj)

        if self.ipvx is not 'v4':
            self.topology.vrf.hld_obj.add_ipv6_multicast_route(
                self.SIP.hld_obj,
                self.MC_GROUP_ADDR.hld_obj,
                self.mc_group,
                self.rpfid1,            # rpfid
                self.punt_on_rpf_fail,  # punt_on_rpf_fail
                False,                  # Punt and forward
                self.enable_rpf_check,
                None)                   # counter
        else:
            self.topology.vrf.hld_obj.add_ipv4_multicast_route(
                self.SIP.hld_obj,
                self.MC_GROUP_ADDR.hld_obj,
                self.mc_group,
                self.rpfid1,            # rpfid
                self.punt_on_rpf_fail,  # punt_on_rpf_fail
                False,                  # Punt and forward
                self.enable_rpf_check,
                None)                   # counter

        if hasattr(self, 'pim_all') and self.pim_all is True:
            self.create_lpts()

    def prepare_punt(self, fwd_hdr_type, source, code, source_lp, destination_lp, lpts_flow_type):
        self.punt_hdr = {
            'fwd_header_type': fwd_hdr_type,
            'source': source,
            'code': code,
            'source_lp': source_lp,
            'destination_lp': destination_lp,
            'lpts_flow_type': lpts_flow_type
        }

    def frame_input_packet(self):

        if self.node_type is node_type_e.MLDP_TAIL_NODE:
            INPUT_LABEL = self.INPUT_LABEL_TAIL
        elif self.node_type is node_type_e.MLDP_BUD_NODE:
            INPUT_LABEL = self.INPUT_LABEL_BUD
        else:
            pass  # head node implementation

        INPUT_SRC_IP = self.SIP
        INPUT_MCAST_DIP = self.MC_GROUP_ADDR

        if not hasattr(self, 'pim_all'):
            PROTO = sdk.la_l4_protocol_e_TCP
        else:
            PROTO = mc_base.PIM_TYPE if self.pim_all is True else sdk.la_l4_protocol_e_TCP

        INPUT_PACKET_BASE = Ether(dst=T.RX_L3_AC_MAC.addr_str,
                                  src=mc_base.SA.addr_str,
                                  type=Ethertype.QinQ.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=Ethertype.Dot1Q.value) / \
            Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
            MPLS(label=INPUT_LABEL.label,
                 ttl=mc_base.TTL) / \
            IPvX(ipvx=self.ipvx,
                 src=self.PACKET_SIP.addr_str,
                 dst=INPUT_MCAST_DIP.addr_str,
                 ttl=mc_base.TTL,
                 proto=PROTO) / \
            TCP() / Raw(load=RAW_PAYLOAD)
        return INPUT_PACKET_BASE

    def frame_expected_packets(self):

        if self.ipvx is 'v4':
            dst_mac = ipv4_mc.get_mc_sa_addr_str(self.MC_GROUP_ADDR)
            ethertype = Ethertype.IPv4.value
        else:
            dst_mac = ipv6_mc.get_mc_sa_addr_str(self.MC_GROUP_ADDR)
            ethertype = Ethertype.IPv6.value

        # forward case
        if self.trap is None:
            EXPECTED_OUTPUT_PACKET_BASE = Ether(dst=dst_mac,
                                                src=T.TX_L3_AC_REG_MAC.addr_str,
                                                type=ethertype) / \
                IPvX(ipvx=self.ipvx,
                     src=self.PACKET_SIP.addr_str,
                     dst=self.MC_GROUP_ADDR.addr_str,
                     ttl=mc_base.TTL - 1) / TCP() / Raw(load=RAW_PAYLOAD)

            EXPECTED_OUTPUT_PACKET_DEF_BASE = Ether(dst=dst_mac,
                                                    src=T.TX_L3_AC_DEF_MAC.addr_str,
                                                    type=ethertype) / \
                IPvX(ipvx=self.ipvx,
                     src=self.PACKET_SIP.addr_str,
                     dst=self.MC_GROUP_ADDR.addr_str,
                     ttl=mc_base.TTL - 1) / TCP() / Raw(load=RAW_PAYLOAD)

            self.INPUT_PACKET, self.EXPECTED_OUTPUT_PACKET = pad_input_and_output_packets(
                self.INPUT_PACKET, EXPECTED_OUTPUT_PACKET_BASE)
            __, self.EXPECTED_OUTPUT_PACKET_DEF = pad_input_and_output_packets(
                self.INPUT_PACKET, EXPECTED_OUTPUT_PACKET_DEF_BASE)

        # punt case
        else:
            EXPECTED_OUTPUT_PACKET = []

            if self.node_type is node_type_e.MLDP_TAIL_NODE:
                self.EXPECTED_OUTPUT_PACKET_PUNT = \
                    Ether(dst=mc_base.HOST_MAC_ADDR, src=mc_base.PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
                    Dot1Q(prio=0, id=0, vlan=mc_base.PUNT_VLAN, type=Ethertype.Punt.value) / \
                    Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                         fwd_header_type=self.punt_hdr['fwd_header_type'],
                         next_header_offset=len(Ether()) + 2 * len(Dot1Q()) + len(MPLS()),
                         source=self.punt_hdr['source'],
                         code=self.punt_hdr['code'],
                         source_sp=T.RX_SYS_PORT_GID,
                         destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                         source_lp=self.punt_hdr['source_lp'],
                         destination_lp=self.punt_hdr['destination_lp'],
                         relay_id=T.VRF_GID,
                         lpts_flow_type = self.punt_hdr['lpts_flow_type']) / \
                    self.INPUT_PACKET

            elif self.node_type is node_type_e.MLDP_BUD_NODE:
                if not hasattr(self, 'pim_all'):
                    PROTO = sdk.la_l4_protocol_e_TCP
                else:
                    PROTO = mc_base.PIM_TYPE if self.pim_all is True else sdk.la_l4_protocol_e_TCP
                self.EXPECTED_OUTPUT_PACKET_PUNT = \
                    Ether(dst=mc_base.HOST_MAC_ADDR, src=mc_base.PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
                    Dot1Q(prio=0, id=0, vlan=mc_base.PUNT_VLAN, type=Ethertype.Punt.value) / \
                    Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
                         fwd_header_type=self.punt_hdr['fwd_header_type'],
                         next_header_offset=len(Ether()) + len(Dot1Q()) + len(MPLS()),
                         source=self.punt_hdr['source'],
                         code=self.punt_hdr['code'],
                         source_sp=self.topology.recycle_ports[self.RCY_SLICE].sys_port.hld_obj.get_gid(),
                         destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
                         source_lp=self.punt_hdr['source_lp'],
                         destination_lp=self.punt_hdr['destination_lp'],
                         relay_id=T.VRF_GID,
                         lpts_flow_type = self.punt_hdr['lpts_flow_type']) / \
                    Ether(dst=self.RECYCLE_PORT_MAC.addr_str, src='00:00:00:00:00:01', type=Ethertype.Dot1Q.value) / \
                    Dot1Q(prio=0, id=0, vlan=self.RECYCLE_VLAN, type=Ethertype.MPLS.value) / \
                    MPLS(label=self.INPUT_LABEL_BUD.label, ttl=mc_base.TTL) / \
                    IPvX(ipvx=self.ipvx, src=self.PACKET_SIP.addr_str, dst=self.MC_GROUP_ADDR.addr_str, ttl=mc_base.TTL, proto=PROTO) / \
                    TCP() / Raw(load=RAW_PAYLOAD)

        if self.node_type is node_type_e.MLDP_BUD_NODE:
            if not hasattr(self, 'pim_all'):
                PROTO = sdk.la_l4_protocol_e_TCP
            else:
                PROTO = mc_base.PIM_TYPE if self.pim_all is True else sdk.la_l4_protocol_e_TCP
            EXPECTED_OUTPUT_PACKET_BASE_MPLS = Ether(dst=T.NH_L3_AC_REG_MAC.addr_str,
                                                     src=T.TX_L3_AC_REG_MAC.addr_str,
                                                     type=Ethertype.MPLS.value) / MPLS(label=self.OUTPUT_LABEL.label,
                                                                                       ttl=mc_base.TTL - 1) / IPvX(ipvx=self.ipvx,
                                                                                                                   src=self.PACKET_SIP.addr_str,
                                                                                                                   dst=self.MC_GROUP_ADDR.addr_str,
                                                                                                                   ttl=mc_base.TTL,
                                                                                                                   proto=PROTO) / TCP() / Raw(load=RAW_PAYLOAD)

            self.INPUT_PACKET, self.EXPECTED_OUTPUT_PACKET_MPLS = pad_input_and_output_packets(
                self.INPUT_PACKET, EXPECTED_OUTPUT_PACKET_BASE_MPLS)

    def create_packets(self):
        self.INPUT_PACKET = self.frame_input_packet()
        self.frame_expected_packets()

    def runtest_and_predict(self):
        ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        expected_packets = []

        # forwarded scenario

        if self.node_type is node_type_e.MLDP_BUD_NODE:
            expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_MPLS, 'slice': T.TX_SLICE_REG,
                                     'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})

        if self.trap is None:
            expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                     'ifg': T.TX_IFG_REG, 'pif': self.output_serdes})
            expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_DEF, 'slice': T.TX_SLICE_DEF,
                                     'ifg': T.TX_IFG_DEF, 'pif': self.output_serdes})
        # punt or drop depending on trap type
        else:
            expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET_PUNT, 'slice': mc_base.INJECT_SLICE,
                                     'ifg': mc_base.INJECT_IFG, 'pif': mc_base.INJECT_PIF_FIRST})

        run_and_compare_list(self, self.device, ingress_packet, expected_packets)

    def do_test_route(self):
        # install the node attributes only if testcase has not explicitly installed it
        if (not hasattr(self, 'retest')) or (hasattr(self, 'retest') and self.retest is not True):
            self._install_mldp_edge_node()
        self.create_packets()
        self.runtest_and_predict()

        if self.node_type is node_type_e.MLDP_BUD_NODE:
            # test get_size()
            group_size = self.mpls_mc_group.get_size()
            self.assertEqual(group_size, 2)

            # test adding an existing member
            with self.assertRaises(sdk.ExistException):
                self.mpls_mc_group.add(self.recycle_l3_ac_port_termination)

            # test get_member
            (mpls_meminfo) = self.mpls_mc_group.get_member(1)
            self.assertIsNone(mpls_meminfo.prefix_object)
            self.assertEqual(mpls_meminfo.l3_port.this, self.recycle_l3_ac_port_termination.this)

            # test deletion of l3_ac_port when in use
            with self.assertRaises(sdk.BusyException):
                self.device.destroy(self.recycle_l3_ac_port_termination)
                self.device.destroy(self.recycle_eth_port)
                self.device.destroy(self.topology.recycle_ports[self.RCY_SLICE].sys_port.hld_obj)

            # remove recycle member and test size
            self.mpls_mc_group.remove(self.recycle_l3_ac_port_termination)
            group_size = self.mpls_mc_group.get_size()
            self.assertEqual(group_size, 1)

            # test remove of a non-member
            with self.assertRaises(sdk.NotFoundException):
                self.mpls_mc_group.remove(self.recycle_l3_ac_port_termination)

    def modify_multicast_route(self):
        if self.ipvx is not 'v4':
            self.topology.vrf.hld_obj.modify_ipv6_multicast_route(
                self.SIP.hld_obj,
                self.MC_GROUP_ADDR.hld_obj,
                self.mc_group,
                self.rpfid1,             # rpfid
                self.punt_on_rpf_fail,   # punt_on_rpf_fail
                False,                   # Punt and forward
                self.enable_rpf_check,
                None)                    # counter
        else:
            self.topology.vrf.hld_obj.modify_ipv4_multicast_route(
                self.SIP.hld_obj,
                self.MC_GROUP_ADDR.hld_obj,
                self.mc_group,
                self.rpfid1,              # rpfid
                self.punt_on_rpf_fail,    # punt_on_rpf_fail
                False,                    # Punt and forward
                self.enable_rpf_check,
                None)                     # counter

    def delete_multicast_route(self):
        # Cleanup
        if self.ipvx is not 'v4':
            self.topology.vrf.hld_obj.delete_ipv6_multicast_route(self.SIP.hld_obj, self.MC_GROUP_ADDR.hld_obj)
        else:
            self.topology.vrf.hld_obj.delete_ipv4_multicast_route(self.SIP.hld_obj, self.MC_GROUP_ADDR.hld_obj)

    def modify_termination_table(self):
        lsr = self.device.get_lsr()

        # update termination table
        if self.node_type is node_type_e.MLDP_TAIL_NODE:
            try:
                lsr.modify_vpn_decap(
                    self.INPUT_LABEL_TAIL, self.topology.vrf.hld_obj, self.rpfid, False, self.decap_obj)
            except BaseException as STATUS:
                self.assertEqual(STATUS.args[0], self.exception)

        elif self.node_type is node_type_e.MLDP_BUD_NODE:
            lsr.modify_vpn_decap(
                self.INPUT_LABEL_BUD, self.topology.vrf.hld_obj, self.rpfid, True, self.decap_obj)
        # head node
        else:
            pass  # implement later

    def get_tx_sys_port(self):
        return self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj

    def get_tx_sys_port_def(self):
        return self.topology.tx_l3_ac_eth_port_def.sys_port.hld_obj

    def get_tx_sys_port_ext(self):
        return self.topology.tx_l3_ac_eth_port_ext.sys_port.hld_obj
