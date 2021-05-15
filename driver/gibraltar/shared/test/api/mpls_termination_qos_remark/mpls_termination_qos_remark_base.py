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

import sys
import unittest
from leaba import sdk
import ip_test_base
from scapy.all import *
import sim_utils
import topology as T
import packet_test_utils as U
from sdk_test_case_base import *

U.parse_ip_after_mpls()


class mpls_termination_qos_remark_base(sdk_test_case_base):
    PRIVATE_DATA = 0x1234567890abcdef
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
    OUTPUT_VID = 0xac
    IP_TTL = 0x80
    MPLS_TTL = 0x40
    VPN_LABEL = sdk.la_mpls_label()
    VPN_LABEL.label = 0x30
    SA = T.mac_addr('be:ef:5d:35:7a:35')

    # QoS remarking
    # Ingress QoS fields
    # Terminated headers
    IN_PCPDEI = sdk.la_vlan_pcpdei()
    IN_PCPDEI.fields.pcp = 2
    IN_PCPDEI.fields.dei = 1

    IN_OUTER_MPLS_TC = sdk.la_mpls_tc()
    IN_OUTER_MPLS_TC.value = 3

    # Forwarding headers
    IN_IP_DSCP = sdk.la_ip_dscp()
    IN_IP_DSCP.value = 20

    # Intermediate tags
    TAG_PIPE_IP_DSCP = sdk.la_ip_dscp()
    TAG_PIPE_IP_DSCP.value = 50

    TAG_UNIFORM_MPLS_TC = sdk.la_mpls_tc()
    TAG_UNIFORM_MPLS_TC.value = 5

    # Egress QoS fields
    # Encapsulating headers
    OUT_PCPDEI = sdk.la_vlan_pcpdei()
    OUT_PCPDEI.fields.pcp = 5
    OUT_PCPDEI.fields.dei = 1

    # Forwarding headers
    OUT_IP_DSCP = sdk.la_ip_dscp()
    OUT_IP_DSCP.value = IN_IP_DSCP.value

    OUT_IP_DSCP_REMARK_DISABLED = sdk.la_ip_dscp()
    OUT_IP_DSCP_REMARK_DISABLED.value = 35

    # IP ECN field
    IP_ECN = 2

    def setUp(self):
        super().setUp()
        self.ip_impl = self.ip_impl_class()
        self.l3_port_impl = self.l3_port_impl_class(self.topology)

        self.add_default_route()
        self.create_packets()
        self.set_egress_tag_mode()
        self.set_l2_egress_vlan_tag()
        self.create_and_assign_qos_profiles()
        self.configure_qos_profiles()

    def tearDown(self):
        self.unassign_and_destroy_qos_profiles()
        super().tearDown()

    def add_default_route(self):
        prefix = self.ip_impl.get_default_prefix()
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.def_nh, self.PRIVATE_DATA_DEFAULT)
        self.has_default_route = True

    def destroy_default_route(self):
        if self.has_default_route:
            prefix = self.ip_impl.get_default_prefix()
            self.ip_impl.delete_route(self.topology.vrf, prefix)
            self.has_default_route = False

    def set_egress_tag_mode(self):
        if self.egress_tagged_mode:
            tag = sdk.la_vlan_tag_t()
            tag.tpid = 0x8100
            tag.tci.fields.pcp = 0
            tag.tci.fields.dei = 0
            tag.tci.fields.vid = self.OUTPUT_VID

            self.l3_port_impl.tx_port.hld_obj.set_egress_vlan_tag(tag, sdk.LA_VLAN_TAG_UNTAGGED)

    def set_l2_egress_vlan_tag(self):
        if self.egress_tagged_mode:
            eve = sdk.la_vlan_edit_command()
            eve.num_tags_to_push = 1
            eve.num_tags_to_pop = 0
            eve.tag0.tpid = 0x8100
            eve.tag0.tci.fields.vid = self.OUTPUT_VID

            self.topology.tx_l2_ac_port_reg.hld_obj.set_egress_vlan_edit_command(eve)

    def egress_l2_headers(self, pcpdei):
        if self.egress_tagged_mode:
            return Ether(dst=self.output_ether_0_dst, src=self.output_ether_0_src, type=U.Ethertype.Dot1Q.value) / \
                U.Dot1QPrio(vlan=self.OUTPUT_VID, pcpdei=pcpdei)
        else:
            return Ether(dst=self.output_ether_0_dst, src=self.output_ether_0_src)

    def create_and_assign_qos_profiles(self):
        # Create new ingress/egress qos profiles
        self.ingress_qos_profile_new = T.ingress_qos_profile(self, self.device)
        self.egress_qos_profile_new = T.egress_qos_profile(self, self.device)

        # Assign new profiles
        rx_port = self.l3_port_impl.rx_one_tag_port
        rx_port.hld_obj.set_ingress_qos_profile(self.ingress_qos_profile_new.hld_obj)
        self.topology.rx_l2_ac_port.hld_obj.set_ingress_qos_profile(self.ingress_qos_profile_new.hld_obj)

        tx_port = self.l3_port_impl.tx_port
        tx_port.hld_obj.set_egress_qos_profile(self.egress_qos_profile_new.hld_obj)
        self.topology.tx_l2_ac_port_reg.hld_obj.set_egress_qos_profile(self.egress_qos_profile_new.hld_obj)

    def unassign_and_destroy_qos_profiles(self):
        # Assign the topology-default profiles, in order to "un-use" the new ones.
        rx_port = self.l3_port_impl.rx_one_tag_port
        rx_port.hld_obj.set_ingress_qos_profile(self.topology.ingress_qos_profile_def.hld_obj)
        self.topology.rx_l2_ac_port.hld_obj.set_ingress_qos_profile(self.topology.ingress_qos_profile_def.hld_obj)

        tx_port = self.l3_port_impl.tx_port
        tx_port.hld_obj.set_egress_qos_profile(self.topology.egress_qos_profile_def.hld_obj)
        self.topology.tx_l2_ac_port_reg.hld_obj.set_egress_qos_profile(self.topology.egress_qos_profile_def.hld_obj)

        # Destroy new profiles
        self.ingress_qos_profile_new.destroy()
        self.egress_qos_profile_new.destroy()

    def configure_qos_profiles(self):
        encap_qos_values = sdk.encapsulating_headers_qos_values()
        encap_qos_values.pcpdei = self.OUT_PCPDEI

        if (self.qos_inheritance_mode == sdk.la_mpls_qos_inheritance_mode_e_PIPE):
            # In PIPE mode, the QoS value of the forwarding header is used, so prepare remarking of IN_IP_DSCP -> OUT_IP_DSCP
            self.ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_dscp(
                sdk.la_ip_version_e_IPV4, self.IN_IP_DSCP, self.TAG_PIPE_IP_DSCP)

            self.egress_qos_profile_new.hld_obj.set_qos_tag_mapping_dscp(
                self.TAG_PIPE_IP_DSCP, self.OUT_IP_DSCP, encap_qos_values)
            self.egress_qos_profile_new.hld_obj.set_qos_tag_mapping_dscp(
                self.IN_IP_DSCP, self.OUT_IP_DSCP_REMARK_DISABLED, encap_qos_values),

        else:
            # In UNIFORM mode, the QoS value of the first terminated label is used, so prepare
            # remarking of IN_OUTER_MPLS_TC -> TAG_UNIFORM_MPLS_TC, and ensure it is not applied when remarking disabled
            self.ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_mpls_tc(
                self.IN_OUTER_MPLS_TC, self.TAG_UNIFORM_MPLS_TC)

            self.egress_qos_profile_new.hld_obj.set_qos_tag_mapping_dscp(
                self.IN_IP_DSCP, self.OUT_IP_DSCP_REMARK_DISABLED, encap_qos_values)

    def create_packets(self):
        INPUT_PACKET_SINGLE_NULL_BASE = \
            Ether(dst=self.input_ether_0_dst, src=self.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            U.Dot1QPrio(vlan=self.input_dot1q_0_vlan, pcpdei=self.IN_PCPDEI.flat) / \
            MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV4, ttl=self.MPLS_TTL, cos=self.IN_OUTER_MPLS_TC.value) / \
            U.IPvX(ipvx=self.ipvx, src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.IP_TTL, dscp=self.IN_IP_DSCP.value, ecn=self.IP_ECN)

        INPUT_PACKET_TWO_NULLS_OUTER_V4_BASE = \
            Ether(dst=self.input_ether_0_dst, src=self.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            U.Dot1QPrio(vlan=self.input_dot1q_0_vlan, pcpdei=self.IN_PCPDEI.flat) / \
            MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV4, ttl=self.MPLS_TTL, cos=self.IN_OUTER_MPLS_TC.value, s=0) / \
            MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV4, ttl=self.MPLS_TTL) / \
            U.IPvX(ipvx=self.ipvx, src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.IP_TTL, dscp=self.IN_IP_DSCP.value, ecn=self.IP_ECN)

        INPUT_PACKET_SINGLE_NULL_VPN_BASE = \
            Ether(dst=self.input_ether_0_dst, src=self.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            U.Dot1QPrio(vlan=self.input_dot1q_0_vlan, pcpdei=self.IN_PCPDEI.flat) / \
            MPLS(label=sdk.LA_MPLS_LABEL_EXPLICIT_NULL_IPV4, ttl=self.MPLS_TTL, cos=self.IN_OUTER_MPLS_TC.value, s=0) / \
            MPLS(label=self.VPN_LABEL.label, ttl=self.MPLS_TTL) / \
            U.IPvX(ipvx=self.ipvx, src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.IP_TTL, dscp=self.IN_IP_DSCP.value, ecn=self.IP_ECN)

        EXPECTED_OUTPUT_PACKET_REMARK_DISABLED_BASE = self.egress_l2_headers(
            self.OUT_PCPDEI.flat) / U.IPvX(
            ipvx=self.ipvx,
            src=self.SIP.addr_str,
            dst=self.DIP.addr_str,
            ttl=self.IP_TTL - 1,
            dscp=self.OUT_IP_DSCP_REMARK_DISABLED.value,
            ecn=self.IP_ECN)

        BASE_INPUT_PACKET_PAYLOAD_SIZE = 4  # need to have data in order to avoid traps
        self.INPUT_PACKET_SINGLE_NULL = U.add_payload(INPUT_PACKET_SINGLE_NULL_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
        self.INPUT_PACKET_TWO_NULLS_OUTER_V4 = U.add_payload(INPUT_PACKET_TWO_NULLS_OUTER_V4_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
        self.INPUT_PACKET_SINGLE_NULL_VPN = U.add_payload(INPUT_PACKET_SINGLE_NULL_VPN_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
        self.EXPECTED_OUTPUT_PACKET_REMARK_DISABLED = U.add_payload(
            EXPECTED_OUTPUT_PACKET_REMARK_DISABLED_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)

    def _test_single_null(self):
        # Disable remarking for IP
        self.ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_enabled(True)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)

        # BOS NULL labels are removed implicitly and not through VPN decap, hence, the
        # QoS inheritance is controlled by the ingress L3 port, and not by
        # vpn_decap
        self.l3_port_impl.rx_one_tag_port.hld_obj.set_qos_inheritance_mode(self.qos_inheritance_mode)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_SINGLE_NULL, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_REMARK_DISABLED, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.ip_impl.delete_route(self.topology.vrf, prefix)
        self.ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_enabled(False)

    def _test_single_null_remark_disabled(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)
        self.l3_port_impl.rx_one_tag_port.hld_obj.set_qos_inheritance_mode(self.qos_inheritance_mode)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_SINGLE_NULL, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_REMARK_DISABLED, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

    def _test_single_null_vpn(self):
        # Disable remarking for IP
        self.ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_enabled(True)

        lsr = self.device.get_lsr()

        decap = lsr.add_vpn_decap(self.VPN_LABEL, self.topology.vrf.hld_obj)
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_SINGLE_NULL_VPN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_REMARK_DISABLED, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)
        self.ip_impl.delete_route(self.topology.vrf, prefix)
        lsr.delete_vpn_decap(decap)
        self.ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_enabled(False)

    def _test_single_null_vpn_remark_disabled(self):
        lsr = self.device.get_lsr()

        decap = lsr.add_vpn_decap(self.VPN_LABEL, self.topology.vrf.hld_obj)
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_SINGLE_NULL_VPN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_REMARK_DISABLED, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)
        self.ip_impl.delete_route(self.topology.vrf, prefix)
        lsr.delete_vpn_decap(decap)

    def _test_two_nulls_outer_v4(self):
        # Disable remarking for IP
        self.ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_enabled(True)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)

        # BOS NULL labels are removed implicitly and not through VPN decap, hence, the
        # QoS inheritance is controlled by the ingress L3 port, and not by
        # vpn_decap
        self.l3_port_impl.rx_one_tag_port.hld_obj.set_qos_inheritance_mode(self.qos_inheritance_mode)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_TWO_NULLS_OUTER_V4, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_REMARK_DISABLED, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.ip_impl.delete_route(self.topology.vrf, prefix)
        self.ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_enabled(False)

    def _test_two_nulls_outer_v4_remark_disabled(self):

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, self.PRIVATE_DATA)

        # BOS NULL labels are removed implicitly and not through VPN decap, hence, the
        # QoS inheritance is controlled by the ingress L3 port, and not by
        # vpn_decap
        self.l3_port_impl.rx_one_tag_port.hld_obj.set_qos_inheritance_mode(self.qos_inheritance_mode)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_TWO_NULLS_OUTER_V4, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_REMARK_DISABLED, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.ip_impl.delete_route(self.topology.vrf, prefix)
