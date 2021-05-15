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

import sys
import unittest
from enum import Enum
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import sim_utils
import topology as T
import packet_test_defs as P
import ip_test_base
from sdk_test_case_base import *
import mtu.mtu_test_utils as MTU
import decor

S.load_contrib('mpls')


class qos_mode(Enum):
    Default = 1
    QoS_Marking = 2
    QoS_ACL = 3


@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
class test_gre_mpls(sdk_test_case_base):

    PRIVATE_DATA = 0x1234567890abcdef
    PRIVATE_DATA_MPLS = 0xabcdef1234567890
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
    SA = T.mac_addr('be:ef:5d:35:7a:35')

    GRE_PORT_GID = 0x901
    GRE_PORT_GID1 = 0x902
    GRE_TUNNEL_DESTINATION_GID = 0x674
    GRE_TUNNEL_DESTINATION_GID1 = 0x675
    GRE_SIP = T.ipv4_addr('12.10.12.11')
    GRE_SIP1 = T.ipv4_addr('14.10.12.11')
    GRE_DIP = T.ipv4_addr('12.1.95.250')
    GRE_DIP1 = T.ipv4_addr('14.1.95.250')
    NEW_TX_L3_AC_DEF_MAC = T.mac_addr('50:52:53:54:55:56')

    OVL_DIP_ROUTE = T.ipv4_addr('21.1.1.0')
    OVL_SIP_ROUTE = T.ipv4_addr('11.1.1.0')
    OVL_IP_PACKET_DMAC = NEW_TX_L3_AC_DEF_MAC.addr_str
    OVL_IP_PACKET_SMAC = '40:11:22:33:44:55'
    OVL_IP_PACKET_DIP = '21.1.1.1'
    OVL_IP_PACKET_SIP = '11.1.1.1'

    UNL_IP_PACKET_SMAC = '00:11:22:33:44:55'

    OVL_DIP_ROUTE_IPv6 = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:0000')
    OVL_SIP_ROUTE_IPv6 = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:0000')

    OVL_IP_PACKET_DIP_IPv6 = '1111:0db8:0a0b:12f0:0000:0000:0000:1111'
    OVL_IP_PACKET_SIP_IPv6 = '2222:0db8:0a0b:12f0:0000:0000:0000:2222'

    IP_TTL = 77
    MPLS_TTL = 88
    OVL_IP_TTL = 99

    GRE_MPLS_DECAP_TERM_INPUT = S.IP(dst=OVL_IP_PACKET_SIP,
                                     src=OVL_IP_PACKET_DIP,
                                     ttl=OVL_IP_TTL)
    GRE_MPLS_ENCAP_TERM_INPUT = S.IP(dst=OVL_IP_PACKET_DIP,
                                     src=OVL_IP_PACKET_SIP,
                                     ttl=OVL_IP_TTL)

    GRE_MPLS_DECAP_TERM_OUT_PIPE = S.IP(dst=OVL_IP_PACKET_SIP,
                                        src=OVL_IP_PACKET_DIP,
                                        ttl=OVL_IP_TTL - 1)

    GRE_MPLS_DECAP_TERM_OUT_UNIFORM = S.IP(dst=OVL_IP_PACKET_SIP,
                                           src=OVL_IP_PACKET_DIP,
                                           ttl=IP_TTL - 1)

    GRE_MPLS_DECAP_TERM_INPUT_IPv6 = S.IPv6(dst=OVL_IP_PACKET_SIP_IPv6,
                                            src=OVL_IP_PACKET_DIP_IPv6,
                                            hlim=OVL_IP_TTL, plen=40)
    GRE_MPLS_ENCAP_TERM_INPUT_IPv6 = S.IPv6(dst=OVL_IP_PACKET_DIP_IPv6,
                                            src=OVL_IP_PACKET_SIP_IPv6,
                                            hlim=OVL_IP_TTL, plen=40)

    SRC_LABEL = sdk.la_mpls_label()
    SRC_LABEL.label = 0x64
    DST_LABEL = sdk.la_mpls_label()
    DST_LABEL.label = 0xf0065

    DST_LABEL1 = sdk.la_mpls_label()
    DST_LABEL1.label = 0xf0066

    # Forwarding headers
    IN_DSCP = sdk.la_ip_dscp()
    IN_DSCP.value = 9

    IN_TOS = sdk.la_ip_tos()
    IN_TOS.fields.ecn = 0
    IN_TOS.fields.dscp = IN_DSCP.value

    TAG_MPLS_TC = sdk.la_mpls_tc()
    TAG_MPLS_TC.value = 3

    OUT_MPLS_TC = sdk.la_mpls_tc()
    OUT_MPLS_TC.value = 4

    OUT_DSCP = sdk.la_ip_dscp()
    OUT_DSCP.value = 31

    OUT_TOS = sdk.la_ip_tos()
    OUT_TOS.fields.ecn = 0
    OUT_TOS.fields.dscp = OUT_DSCP.value

    QOS_GROUPID = 1

    QOS_COUNTER_OFFSET = 1
    QOS_MARK_DSCP = sdk.la_ip_dscp()
    QOS_MARK_DSCP.value = 17

    encap_qos_values = sdk.encapsulating_headers_qos_values()
    encap_qos_values.tos = OUT_TOS
    encap_qos_values.tc = OUT_MPLS_TC
    encap_qos_values.use_for_inner_labels = True

    MPLS_OVER_GRE_PACKET_DOUBLE_LABEL_BASE = \
        S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str,
                src=UNL_IP_PACKET_SMAC) / \
        S.IP(dst=GRE_SIP.addr_str,
             src=GRE_DIP.addr_str,
             id=0,
             flags=2,
             ttl=IP_TTL,
             tos=IN_TOS.flat) / \
        S.GRE(proto=U.Ethertype.MPLS.value) / \
        MPLS(label=DST_LABEL.label,
             ttl=MPLS_TTL - 2,
             s=0) / \
        MPLS(label=DST_LABEL1.label,
             ttl=MPLS_TTL) / \
        S.IP(dst=OVL_IP_PACKET_SIP,
             src=OVL_IP_PACKET_DIP,
             ttl=OVL_IP_TTL) / \
        S.TCP()

    MPLS_OVER_GRE_PACKET_DOUBLE_LABEL_BASE_IPv6 = \
        S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str,
                src=UNL_IP_PACKET_SMAC) / \
        S.IP(dst=GRE_SIP.addr_str,
             src=GRE_DIP.addr_str,
             id=0,
             flags=2,
             ttl=IP_TTL,
             tos=IN_TOS.flat) / \
        S.GRE(proto=U.Ethertype.MPLS.value) / \
        MPLS(label=DST_LABEL.label,
             ttl=MPLS_TTL - 2,
             s=0) / \
        MPLS(label=DST_LABEL1.label,
             ttl=MPLS_TTL) / \
        S.IPv6(dst=OVL_IP_PACKET_SIP_IPv6,
               src=OVL_IP_PACKET_DIP_IPv6,
               hlim=OVL_IP_TTL, plen=40) / \
        S.TCP()

    def setUp(self):
        super().setUp()
        self.ip_impl = ip_test_base.ipv4_test_base
        self.ipv6_impl = ip_test_base.ipv6_test_base
        self.l3_port_impl = T.ip_l3_ac_base(self.topology)
        self.svi_port_impl = T.ip_svi_base(self.topology)

        # enable ipv4/MPLS forwarding
        self.topology.tx_l3_ac_reg.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_UC, True)
        self.topology.tx_l3_ac_reg.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV6_UC, True)
        self.topology.tx_l3_ac_reg.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_MPLS, True)
        self.topology.tx_l3_ac_def.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_UC, True)
        self.topology.tx_l3_ac_def.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV6_UC, True)
        self.topology.tx_l3_ac_def.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_MPLS, True)
        self.topology.tx_l3_ac_ext.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_UC, True)
        self.topology.tx_l3_ac_ext.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV6_UC, True)
        self.topology.tx_l3_ac_ext.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_MPLS, True)

        # make the l3 port address unicast mac address
        self.topology.tx_l3_ac_def.hld_obj.set_mac(
            self.NEW_TX_L3_AC_DEF_MAC.hld_obj)

        self.topology.tx_l3_ac_reg.hld_obj.set_vrf(self.topology.vrf2.hld_obj)

        self.topology.rx_svi.hld_obj.set_active(True)
        self.topology.rx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_MPLS, True)
        self.topology.tx_svi.hld_obj.set_active(True)
        self.topology.tx_svi.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_MPLS, True)

        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)

        self.add_default_route()

    def tearDown(self):
        self.destroy_default_route()
        super().tearDown()

    def add_default_route(self):
        prefix = self.ip_impl.get_default_prefix()
        self.ip_impl.add_route(self.topology.vrf, prefix,
                               self.svi_port_impl.def_nh,
                               self.PRIVATE_DATA_DEFAULT)

        prefix_v6 = self.ipv6_impl.get_default_prefix()
        prefix_v6 = self.ipv6_impl.get_default_prefix()
        self.ipv6_impl.add_route(self.topology.vrf, prefix_v6,
                                 self.svi_port_impl.def_nh,
                                 self.PRIVATE_DATA_DEFAULT)
        self.has_default_route = True

    def destroy_default_route(self):
        if self.has_default_route:
            prefix = self.ip_impl.get_default_prefix()
            self.ip_impl.delete_route(self.topology.vrf, prefix)
            prefix_v6 = self.ipv6_impl.get_default_prefix()
            self.ipv6_impl.delete_route(self.topology.vrf, prefix_v6)
            self.has_default_route = False

    def gre_port_setup(self, gid, unl_vrf, sip, dip, vrf):
        gre_tunnel = self.device.create_gre_port(
            gid,
            unl_vrf.hld_obj,
            sip.hld_obj,
            dip.hld_obj,
            vrf.hld_obj,
            self.topology.ingress_qos_profile_def.hld_obj,
            self.topology.egress_qos_profile_def.hld_obj)

        # set the counter
        self.l3_egress_counter = self.device.create_counter(1)
        self.l3_ingress_counter = self.device.create_counter(1)
        gre_tunnel.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.l3_egress_counter)
        gre_tunnel.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.l3_ingress_counter)

        # enable ipv4/ipv6/MPLS on gre port
        gre_tunnel.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        gre_tunnel.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)
        gre_tunnel.set_protocol_enabled(sdk.la_l3_protocol_e_MPLS, True)

        gre_tunnel.set_lp_attribute_inheritance_mode(sdk.la_lp_attribute_inheritance_mode_e_PORT)
        return gre_tunnel

    def gre_port_single_path(self):
        self.gre_tunnel = self.gre_port_setup(self.GRE_PORT_GID, self.topology.vrf2,
                                              self.GRE_SIP, self.GRE_DIP, self.topology.vrf)

    def destory_gre_port_single_path(self):
        self.device.destroy(self.gre_destination)
        self.device.destroy(self.gre_tunnel)
        self.device.destroy(self.l3_egress_counter)
        self.device.destroy(self.l3_ingress_counter)

    def create_simple_qos_acl(self):
        ''' Create a QoS ACL. '''
        self.device.set_acl_scaled_enabled(False)
        acl1 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)
        self.assertNotEqual(acl1, None)

        count = acl1.get_count()
        self.assertEqual(count, 0)

        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_IPV4_DIP
        f1.val.ipv4_dip.s_addr = self.GRE_SIP.to_num()
        f1.mask.ipv4_dip.s_addr = 0xffffff00
        k1.append(f1)

        commands = []
        action1 = sdk.la_acl_command_action()
        action1.type = sdk.la_acl_action_type_e_COUNTER_TYPE
        action1.data.counter_type = sdk.la_acl_counter_type_e_DO_QOS_COUNTING
        commands.append(action1)

        action2 = sdk.la_acl_command_action()
        action2.type = sdk.la_acl_action_type_e_QOS_OR_METER_COUNTER_OFFSET
        action2.data.qos_offset = self.QOS_COUNTER_OFFSET
        commands.append(action2)

        action3 = sdk.la_acl_command_action()
        action3.type = sdk.la_acl_action_type_e_ENCAP_EXP
        action3.data.encap_exp = self.TAG_MPLS_TC.value
        commands.append(action3)

        action4 = sdk.la_acl_command_action()
        action4.type = sdk.la_acl_action_type_e_REMARK_GROUP
        action4.data.remark_group = self.QOS_GROUPID
        commands.append(action4)

        acl1.append(k1, commands)
        count = acl1.get_count()
        self.assertEqual(count, 1)

        return acl1

    def _test_gre_decap_mpls_pop_double_label(self, ttl_pipe_mode=True, test_qos=qos_mode.Default, is_ipv6=False):
        self.gre_destination = self.device.create_ip_tunnel_destination(
            self.GRE_TUNNEL_DESTINATION_GID,
            self.gre_tunnel,
            self.topology.nh_svi_def.hld_obj)

        if ttl_pipe_mode:
            self.gre_tunnel.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
        else:
            self.gre_tunnel.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_UNIFORM)

        if test_qos != qos_mode.Default:
            l3_ingress_qos_profile = T.ingress_qos_profile(self, self.device)

            if test_qos == qos_mode.QoS_ACL:
                acl1 = self.create_simple_qos_acl()

                # Attach a Q counter
                q_counter = self.device.create_counter(8)
                self.topology.tx_l3_ac_reg.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_QOS, q_counter)

                # Attach the QoS ACL
                ipv4_acls = []
                ipv4_acls.append(acl1)
                acl_group = []
                acl_group = self.device.create_acl_group()
                acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)
                l3_ingress_qos_profile.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)
            else:
                l3_ingress_qos_profile.hld_obj.set_qos_tag_mapping_enabled(True)
                l3_ingress_qos_profile.hld_obj.set_qos_group_mapping(
                    sdk.la_ip_version_e_IPV4, self.IN_DSCP, self.QOS_GROUPID)
                l3_ingress_qos_profile.hld_obj.set_qos_group_mapping(
                    sdk.la_ip_version_e_IPV6, self.IN_DSCP, self.QOS_GROUPID)

            l3_egress_qos_profile = T.egress_qos_profile(self, self.device, sdk.la_egress_qos_marking_source_e_QOS_GROUP)
            l3_egress_qos_profile.hld_obj.set_qos_group_mapping_mpls_tc(
                self.QOS_GROUPID, self.OUT_MPLS_TC, self.encap_qos_values)

            self.topology.tx_l3_ac_reg.hld_obj.set_ingress_qos_profile(l3_ingress_qos_profile.hld_obj)
            self.topology.tx_l3_ac_def.hld_obj.set_egress_qos_profile(l3_egress_qos_profile.hld_obj)

            expected_mpls_cos = self.OUT_MPLS_TC.value
        else:
            expected_mpls_cos = 0

        lsr = self.device.get_lsr()
        nhlfe = self.device.create_mpls_php_nhlfe(
            self.svi_port_impl.def_nh.hld_obj)
        lsr.add_route(self.DST_LABEL, nhlfe, self.PRIVATE_DATA)

        if is_ipv6:
            expected_packet_base = \
                S.Ether(dst=T.NH_SVI_DEF_MAC.addr_str,
                        src=T.TX_SVI_MAC.addr_str,
                        type=U.Ethertype.MPLS.value) / \
                MPLS(label=self.DST_LABEL1.label,
                     ttl=self.MPLS_TTL if ttl_pipe_mode else self.IP_TTL - 1,
                     cos=expected_mpls_cos) / \
                S.IPv6(dst=self.OVL_IP_PACKET_SIP_IPv6,
                       src=self.OVL_IP_PACKET_DIP_IPv6,
                       hlim=self.OVL_IP_TTL, plen=40) / \
                S.TCP()

            input_packet, input_packet_payload_size = U.enlarge_packet_to_min_length(
                self.MPLS_OVER_GRE_PACKET_DOUBLE_LABEL_BASE_IPv6)
            expected_packet = U.add_payload(expected_packet_base, input_packet_payload_size)

            U.run_and_compare(self, self.device,
                              input_packet, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                              expected_packet, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_SVI_DEF)
        else:
            expected_packet_base = \
                S.Ether(dst=T.NH_SVI_DEF_MAC.addr_str,
                        src=T.TX_SVI_MAC.addr_str,
                        type=U.Ethertype.MPLS.value) / \
                MPLS(label=self.DST_LABEL1.label,
                     ttl=self.MPLS_TTL if ttl_pipe_mode else self.IP_TTL - 1,
                     cos=expected_mpls_cos) / \
                S.IP(dst=self.OVL_IP_PACKET_SIP,
                     src=self.OVL_IP_PACKET_DIP,
                     ttl=self.OVL_IP_TTL) / \
                S.TCP()

            input_packet, input_packet_payload_size = U.enlarge_packet_to_min_length(self.MPLS_OVER_GRE_PACKET_DOUBLE_LABEL_BASE)
            expected_packet = U.add_payload(expected_packet_base, input_packet_payload_size)

            U.run_and_compare(self, self.device,
                              input_packet, T.TX_SLICE_REG,
                              T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                              expected_packet, T.TX_SLICE_DEF,
                              T.TX_IFG_DEF, T.FIRST_SERDES_SVI_DEF)

        lsr.delete_route(self.DST_LABEL)
        self.device.destroy(nhlfe)

        packets, _ = self.l3_ingress_counter.read(0, True, True)
        self.assertEqual(packets, 1)

        if test_qos != qos_mode.Default:
            if test_qos == qos_mode.QoS_ACL:
                # Verify Q counter
                packet_count, byte_count = q_counter.read(self.QOS_COUNTER_OFFSET, True, True)
                self.assertEqual(packet_count, 1)
                U.assertPacketLengthIngress(self, input_packet, T.TX_SLICE_REG, byte_count)

                l3_ingress_qos_profile.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

            self.topology.tx_l3_ac_reg.hld_obj.set_ingress_qos_profile(
                self.topology.ingress_qos_profile_def.hld_obj)
            self.topology.tx_l3_ac_def.hld_obj.set_egress_qos_profile(
                self.topology.egress_qos_profile_def.hld_obj)
            l3_ingress_qos_profile.destroy()
            l3_egress_qos_profile.destroy()

    def _test_mpls_decap_gre_encap_single_path(self, is_ipv6=False):
        self.topology.rx_svi.hld_obj.set_active(True)
        self.gre_destination = self.device.create_ip_tunnel_destination(
            self.GRE_TUNNEL_DESTINATION_GID,
            self.gre_tunnel,
            self.topology.nh_l3_ac_reg.hld_obj)

        gre_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_1)
        gre_ecmp.add_member(self.gre_destination)

        lsr = self.device.get_lsr()
        lsr.add_route(self.SRC_LABEL, gre_ecmp, self.PRIVATE_DATA)

        if is_ipv6:
            input_packet_base = \
                S.Ether(dst=T.RX_SVI_MAC.addr_str, src=self.OVL_IP_PACKET_SMAC, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
                MPLS(label=self.SRC_LABEL.label, ttl=self.MPLS_TTL) / \
                self.GRE_MPLS_ENCAP_TERM_INPUT_IPv6 / \
                S.TCP()
        else:
            input_packet_base = \
                S.Ether(dst=T.RX_SVI_MAC.addr_str, src=self.OVL_IP_PACKET_SMAC, type=U.Ethertype.Dot1Q.value) / \
                S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1) / \
                MPLS(label=self.SRC_LABEL.label, ttl=self.MPLS_TTL) / \
                self.GRE_MPLS_ENCAP_TERM_INPUT / \
                S.TCP()

        if is_ipv6:
            expected_packet_base = \
                S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str,
                        src=T.TX_L3_AC_REG_MAC.addr_str) / \
                S.IP(dst=self.GRE_DIP.addr_str,
                     src=self.GRE_SIP.addr_str,
                     id=0,
                     flags=2,
                     ttl=255) / \
                S.GRE(proto=0x86DD) / \
                S.IPv6(dst=self.OVL_IP_PACKET_DIP_IPv6,
                       src=self.OVL_IP_PACKET_SIP_IPv6,
                       hlim=self.OVL_IP_TTL, plen=40) / \
                S.TCP()
        else:
            expected_packet_base = \
                S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str,
                        src=T.TX_L3_AC_REG_MAC.addr_str) / \
                S.IP(dst=self.GRE_DIP.addr_str,
                     src=self.GRE_SIP.addr_str,
                     id=0,
                     flags=2,
                     ttl=255) / \
                S.GRE() / \
                S.IP(dst=self.OVL_IP_PACKET_DIP,
                     src=self.OVL_IP_PACKET_SIP,
                     ttl=self.OVL_IP_TTL) / \
                S.TCP()

        input_packet, input_packet_payload_size = U.enlarge_packet_to_min_length(input_packet_base)
        expected_packet = U.add_payload(expected_packet_base, input_packet_payload_size)

        U.run_and_compare(self, self.device, input_packet,
                          T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          expected_packet,
                          T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        lsr.delete_route(self.SRC_LABEL)
        self.device.destroy(gre_ecmp)

        packets, byte_count = self.l3_egress_counter.read(0, True, True)
        self.assertEqual(packets, 1)
        U.assertPacketLengthEgress(self, expected_packet, byte_count)

    def test_gre_decap_mpls_pop_double_label(self):
        '''
        GRE DECAP followed by MPLS pop double label
        '''
        self.gre_port_single_path()
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
        self._test_gre_decap_mpls_pop_double_label()
        self.destory_gre_port_single_path()

    def test_gre_decap_mpls_pop_double_label_uniform(self):
        '''
        GRE DECAP followed by MPLS pop double label with UNIFORM ttl
        '''
        self.gre_port_single_path()

        self._test_gre_decap_mpls_pop_double_label(ttl_pipe_mode=False)

        self.destory_gre_port_single_path()

    def test_gre_decap_mpls_pop_double_label_ipv6(self):
        '''
        GRE DECAP followed by MPLS pop double label
        '''
        self.gre_port_single_path()
        self.device.set_ttl_inheritance_mode(sdk.la_mpls_ttl_inheritance_mode_e_PIPE)
        self._test_gre_decap_mpls_pop_double_label(is_ipv6=True)
        self.destory_gre_port_single_path()

    def test_gre_decap_mpls_pop_double_label_uniform_ipv6(self):
        '''
        GRE DECAP followed by MPLS pop double label with UNIFORM ttl
        '''
        self.gre_port_single_path()

        self._test_gre_decap_mpls_pop_double_label(ttl_pipe_mode=False, is_ipv6=True)

        self.destory_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_mpls_decap_gre_encap_single_path(self):
        '''
        MPLS terminate then GRE ENCAP
        '''
        self.gre_port_single_path()
        self._test_mpls_decap_gre_encap_single_path()
        self.destory_gre_port_single_path()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_mpls_decap_gre_encap_single_path_ipv6(self):
        '''
        MPLS terminate then GRE ENCAP
        '''
        self.gre_port_single_path()
        self._test_mpls_decap_gre_encap_single_path(is_ipv6=True)
        self.destory_gre_port_single_path()


if __name__ == '__main__':
    unittest.main()
