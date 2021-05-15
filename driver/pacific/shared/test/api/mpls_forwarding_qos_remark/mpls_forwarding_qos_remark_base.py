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
from scapy.all import *
import sim_utils
import topology as T
import packet_test_utils as U

U.parse_ip_after_mpls()


class mpls_forwarding_qos_remark_base:
    SA = T.mac_addr('be:ef:5d:35:7a:35')
    MPLS_TTL = 0x88
    IP_TTL = 0x90
    SMALLER_IP_TTL = 0x80
    INPUT_LABEL = sdk.la_mpls_label()
    INPUT_LABEL.label = 0x64
    INPUT_LABEL1 = sdk.la_mpls_label()
    INPUT_LABEL1.label = 0x63
    OUTPUT_LABEL = sdk.la_mpls_label()
    OUTPUT_LABEL.label = 0x65
    PRIVATE_DATA = 0x1234567890abcdef
    OUTPUT_VID = 0xac

    # QoS remarking
    # Ingress QoS fields
    # Terminated headers
    EGRESS_QOS_COUNTER_OFFSET = 2

    IN_PCPDEI = sdk.la_vlan_pcpdei()
    IN_PCPDEI.fields.pcp = 2
    IN_PCPDEI.fields.dei = 1

    # Forwarding and decapsulated headers
    IN_OUTER_MPLS_TC = sdk.la_mpls_tc()
    IN_OUTER_MPLS_TC.value = 1

    IN_INNER_MPLS_TC = sdk.la_mpls_tc()
    IN_INNER_MPLS_TC.value = 2

    IN_IP_DSCP = sdk.la_ip_dscp()
    IN_IP_DSCP.value = 40

    # Intermediate tags
    TAG_OUTER_MPLS_TC = sdk.la_mpls_tc()
    TAG_OUTER_MPLS_TC.value = 3

    # Egress QoS fields
    # Forwarding headers
    OUT_OUTER_MPLS_TC = sdk.la_mpls_tc()
    OUT_OUTER_MPLS_TC.value = 5

    OUT_PHP_OUTER_MPLS_TC = sdk.la_mpls_tc()
    OUT_PHP_OUTER_MPLS_TC.value = 6

    OUT_IP_DSCP = sdk.la_ip_dscp()
    OUT_IP_DSCP.value = 35

    # Encapsulating headers
    OUT_PCPDEI = sdk.la_vlan_pcpdei()
    OUT_PCPDEI.fields.pcp = 5
    OUT_PCPDEI.fields.dei = 1

    # IP ECN field
    IP_ECN = 3

    my_device = None

    @classmethod
    def initialize_device(cls):
        cls.my_device = U.sim_utils.create_device(2)
        cls._objects_ids_to_keep = []

    @classmethod
    def destroy_device(cls):
        cls.my_device.tearDown()

    def setUp(self):
        self.maxDiff = None  # Show whole strings on failures (unittest variable)

        self.device = mpls_forwarding_qos_remark_base.my_device

        self.topology = T.topology(self, self.device)
        self.l3_port_impl = self.l3_port_impl_class(self.topology)

        self.create_packets()
        self.set_egress_tag_mode()
        self.set_l2_egress_vlan_tag()
        self.create_and_assign_qos_profiles()
        self.configure_qos_profiles()

        if not self.__class__._objects_ids_to_keep:
            self._add_objects_to_keep()

    def tearDown(self):
        self.unassign_and_destroy_qos_profiles()
        self.device.clear_device(self.__class__._objects_ids_to_keep)
        self.topology.reset(self.device, keep_inject_ports=True)
        self.topology = None

    def _add_objects_to_keep(self):
        self._add_topology_inject_ports()
        self._add_topology_recycle_ports()

    def _add_topology_inject_ports(self):
        for pi_port in self.topology.inject_ports:
            if pi_port is None:
                continue
            self.__class__._objects_ids_to_keep.append(pi_port.hld_obj.oid())
            self.__class__._objects_ids_to_keep.append(pi_port.sys_port.hld_obj.oid())
            self.__class__._objects_ids_to_keep.append(pi_port.sys_port.hld_obj.oid())
            self.__class__._objects_ids_to_keep.append(pi_port.pci_port.hld_obj.oid())

    def _add_topology_recycle_ports(self):
        for rcy_port in self.topology.recycle_ports:
            if rcy_port is None:
                continue
            self.__class__._objects_ids_to_keep.append(rcy_port.sys_port.hld_obj.oid())
            self.__class__._objects_ids_to_keep.append(rcy_port.sys_port.voq_set.oid())
            self.__class__._objects_ids_to_keep.append(rcy_port.rcy_port.hld_obj.oid())

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
        self.ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_enabled(True)
        self.egress_qos_profile_new = T.egress_qos_profile(self, self.device)

        # Assign new profiles
        rx_port = self.l3_port_impl.rx_one_tag_port
        rx_port.hld_obj.set_ingress_qos_profile(self.ingress_qos_profile_new.hld_obj)
        self.topology.rx_l2_ac_port.hld_obj.set_ingress_qos_profile(self.ingress_qos_profile_new.hld_obj)

        tx_port = self.l3_port_impl.tx_port
        tx_port.hld_obj.set_egress_qos_profile(self.egress_qos_profile_new.hld_obj)
        self.topology.tx_l2_ac_port_reg.hld_obj.set_egress_qos_profile(self.egress_qos_profile_new.hld_obj)

        self.egress_counter = self.device.create_counter(sdk.LA_NUM_EGRESS_TRAFFIC_CLASSES)
        tx_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_QOS, self.egress_counter)

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
        encap_qos_values.tc = self.OUT_OUTER_MPLS_TC
        encap_qos_values.use_for_inner_labels = True

        if self.qos_inheritance_mode == sdk.la_mpls_qos_inheritance_mode_e_PIPE:
            # In PIPE mode:
            # - In MPLS-SWAP the QoS value of the forwarding header is used.
            # - In MPLS-PHP the QoS value of the exposed header is used.

            # For SWAP prepare remarking of IN_OUTER_MPLS_TC->OUT_OUTER_MPLS_TC
            self.ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_mpls_tc(
                self.IN_OUTER_MPLS_TC, self.TAG_OUTER_MPLS_TC)

            self.ingress_qos_profile_new.hld_obj.set_encap_qos_tag_mapping(
                self.IN_OUTER_MPLS_TC, self.TAG_OUTER_MPLS_TC)

            self.egress_qos_profile_new.hld_obj.set_qos_tag_mapping_mpls_tc(
                self.TAG_OUTER_MPLS_TC, self.OUT_OUTER_MPLS_TC, encap_qos_values)

            # For PHP to IP prepare remarking of IN_IP_DSCP (which doesn't ungergo any ingress mapping) -> OUT_IP_DSCP
            self.egress_qos_profile_new.hld_obj.set_qos_tag_mapping_dscp(
                self.IN_IP_DSCP, self.OUT_IP_DSCP, encap_qos_values)

            # For PHP to MPLS prepare remarking of IN_INNER_MPLS_TC (which doesn't
            # ungergo any ingress mapping) -> OUT_PHP_OUTER_MPLS_TC
            self.egress_qos_profile_new.hld_obj.set_qos_tag_mapping_mpls_tc(
                self.IN_INNER_MPLS_TC, self.OUT_PHP_OUTER_MPLS_TC, encap_qos_values)
        else:
            # In UNIFORM mode:
            # - In MPLS-SWAP the behavior is the same as in PIPE mode.
            # - In MPLS-PHP the QoS value of the first terminated label is used

            # For SWAP prepare remarking of IN_OUTER_MPLS_TC->OUT_OUTER_MPLS_TC
            # This config also affects PHP to MPLS, because the OUTER label is used to mark the exposed label.
            self.ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_mpls_tc(
                self.IN_OUTER_MPLS_TC, self.TAG_OUTER_MPLS_TC)

            self.egress_qos_profile_new.hld_obj.set_qos_tag_mapping_mpls_tc(
                self.TAG_OUTER_MPLS_TC, self.OUT_OUTER_MPLS_TC, encap_qos_values)

            # For PHP to IP prepare remarking of IN_OUTER_MPLS_TC -> OUT_IP_DSCP
            self.ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_mpls_tc(
                self.IN_OUTER_MPLS_TC, self.TAG_OUTER_MPLS_TC)
            self.egress_qos_profile_new.hld_obj.set_qos_tag_mapping_dscp(
                self.IN_IP_DSCP, self.OUT_IP_DSCP, encap_qos_values)

        self.egress_qos_profile_new.hld_obj.set_counter_offset_mapping(self.TAG_OUTER_MPLS_TC, self.EGRESS_QOS_COUNTER_OFFSET)

    def create_packets(self):
        INPUT_PACKET_BASE = Ether(dst=self.input_ether_0_dst,
                                  src=self.SA.addr_str,
                                  type=U.Ethertype.Dot1Q.value) / U.Dot1QPrio(vlan=self.input_dot1q_0_vlan,
                                                                              pcpdei=self.IN_PCPDEI.flat) / MPLS(label=self.INPUT_LABEL.label,
                                                                                                                 ttl=self.MPLS_TTL,
                                                                                                                 cos=self.IN_OUTER_MPLS_TC.value) / U.IPvX(ipvx=self.ipvx,
                                                                                                                                                           src=self.SIP.addr_str,
                                                                                                                                                           dst=self.DIP.addr_str,
                                                                                                                                                           ttl=self.IP_TTL,
                                                                                                                                                           dscp=self.IN_IP_DSCP.value,
                                                                                                                                                           ecn=self.IP_ECN)
        self.INPUT_PACKET, BASE_INPUT_PACKET_PAYLOAD_SIZE = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        self.INPUT_PACKET_SMALLER_INNER_TTL = self.INPUT_PACKET.copy()
        if self.ipvx == 'v4':
            self.INPUT_PACKET_SMALLER_INNER_TTL[IP].ttl = self.SMALLER_IP_TTL
        else:
            self.INPUT_PACKET_SMALLER_INNER_TTL[IPv6].hlim = self.SMALLER_IP_TTL

        INPUT_PACKET_DOUBLE_LABEL_BASE = \
            Ether(dst=self.input_ether_0_dst, src=self.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            U.Dot1QPrio(vlan=self.input_dot1q_0_vlan, pcpdei=self.IN_PCPDEI.flat) / \
            MPLS(label=self.INPUT_LABEL.label, ttl=self.MPLS_TTL, cos=self.IN_OUTER_MPLS_TC.value, s=0) / \
            MPLS(label=self.INPUT_LABEL1.label, ttl=self.MPLS_TTL, cos=self.IN_INNER_MPLS_TC.value) / \
            U.IPvX(ipvx=self.ipvx, src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.IP_TTL, dscp=self.IN_IP_DSCP.value, ecn=self.IP_ECN)
        self.INPUT_PACKET_DOUBLE_LABEL = U.add_payload(INPUT_PACKET_DOUBLE_LABEL_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)

        EXPECTED_OUTPUT_SWAP_PACKET_BASE = \
            self.egress_l2_headers(self.OUT_PCPDEI.flat) / \
            MPLS(label=self.OUTPUT_LABEL.label, ttl=self.MPLS_TTL - 1, cos=self.OUT_OUTER_MPLS_TC.value) / \
            U.IPvX(ipvx=self.ipvx, src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.IP_TTL, dscp=self.IN_IP_DSCP.value, ecn=self.IP_ECN)
        self.EXPECTED_OUTPUT_SWAP_PACKET = U.add_payload(EXPECTED_OUTPUT_SWAP_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)

        EXPECTED_OUTPUT_SWAP_PACKET_DOUBLE_LABEL_BASE = \
            self.egress_l2_headers(self.OUT_PCPDEI.flat) / \
            MPLS(label=self.OUTPUT_LABEL.label, ttl=self.MPLS_TTL - 1, cos=self.OUT_OUTER_MPLS_TC.value, s=0) / \
            MPLS(label=self.INPUT_LABEL1.label, ttl=self.MPLS_TTL, cos=self.IN_INNER_MPLS_TC.value) / \
            U.IPvX(ipvx=self.ipvx, src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.IP_TTL, dscp=self.IN_IP_DSCP.value, ecn=self.IP_ECN)
        self.EXPECTED_OUTPUT_SWAP_PACKET_DOUBLE_LABEL = U.add_payload(
            EXPECTED_OUTPUT_SWAP_PACKET_DOUBLE_LABEL_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)

        if self.qos_inheritance_mode == sdk.la_mpls_qos_inheritance_mode_e_PIPE:
            EXPECTED_OUTPUT_PHP_TO_IP_PACKET_BASE = \
                self.egress_l2_headers(self.OUT_PCPDEI.flat) / \
                U.IPvX(ipvx=self.ipvx, src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.IP_TTL, dscp=self.OUT_IP_DSCP.value, ecn=self.IP_ECN)
            self.EXPECTED_OUTPUT_PHP_TO_IP_PACKET = U.add_payload(
                EXPECTED_OUTPUT_PHP_TO_IP_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
        else:
            EXPECTED_OUTPUT_PHP_TO_IP_PACKET_BASE = \
                self.egress_l2_headers(self.OUT_PCPDEI.flat) / \
                U.IPvX(ipvx=self.ipvx, src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.MPLS_TTL - 1, dscp=self.OUT_IP_DSCP.value, ecn=self.IP_ECN)
            self.EXPECTED_OUTPUT_PHP_TO_IP_PACKET = U.add_payload(
                EXPECTED_OUTPUT_PHP_TO_IP_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)

            self.EXPECTED_OUTPUT_PHP_TO_IP_PACKET_SMALLER_TTL = self.EXPECTED_OUTPUT_PHP_TO_IP_PACKET.copy()
            if self.ipvx == 'v4':
                self.EXPECTED_OUTPUT_PHP_TO_IP_PACKET_SMALLER_TTL[IP].ttl = self.SMALLER_IP_TTL
            else:
                self.EXPECTED_OUTPUT_PHP_TO_IP_PACKET_SMALLER_TTL[IPv6].hlim = self.SMALLER_IP_TTL

        if self.qos_inheritance_mode == sdk.la_mpls_qos_inheritance_mode_e_PIPE:
            # In PIPE mode, the INNER label is used as QoS indication, so can define a marking based on the INNER label
            EXPECTED_OUTPUT_PHP_TO_MPLS_PACKET_BASE = \
                self.egress_l2_headers(self.OUT_PCPDEI.flat) / \
                MPLS(label=self.INPUT_LABEL1.label, ttl=self.MPLS_TTL - 1, cos=self.OUT_PHP_OUTER_MPLS_TC.value) / \
                U.IPvX(ipvx=self.ipvx, src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.IP_TTL, dscp=self.IN_IP_DSCP.value, ecn=self.IP_ECN)
            self.EXPECTED_OUTPUT_PHP_TO_MPLS_PACKET = U.add_payload(
                EXPECTED_OUTPUT_PHP_TO_MPLS_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
        else:
            # In UNIFORM mode, the OUTER label is used as QoS. Since a mapping of
            # OUTER is also set for SWAP, that setting affects this packet
            EXPECTED_OUTPUT_PHP_TO_MPLS_PACKET_BASE = \
                self.egress_l2_headers(self.OUT_PCPDEI.flat) / \
                MPLS(label=self.INPUT_LABEL1.label, ttl=self.MPLS_TTL - 1, cos=self.OUT_OUTER_MPLS_TC.value) / \
                U.IPvX(ipvx=self.ipvx, src=self.SIP.addr_str, dst=self.DIP.addr_str, ttl=self.IP_TTL, dscp=self.IN_IP_DSCP.value, ecn=self.IP_ECN)
            self.EXPECTED_OUTPUT_PHP_TO_MPLS_PACKET = U.add_payload(
                EXPECTED_OUTPUT_PHP_TO_MPLS_PACKET_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)


class ipv4_test:
    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')
    ipvx = 'v4'


class ipv6_test:
    SIP = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')
    DIP = T.ipv6_addr('1111:0db8:0a0b:12f0:0000:0000:0000:1111')
    ipvx = 'v6'


class rx_svi_test:
    l3_port_impl_class = T.ip_svi_base

    input_ether_0_dst = T.RX_SVI_MAC.addr_str
    input_dot1q_0_vlan = T.RX_L2_AC_PORT_VID1
    output_ether_0_dst = T.NH_SVI_REG_MAC.addr_str
    output_ether_0_src = T.TX_SVI_MAC.addr_str


class rx_l3_ac_test:
    l3_port_impl_class = T.ip_l3_ac_base

    input_ether_0_dst = T.RX_L3_AC_ONE_TAG_MAC.addr_str
    input_dot1q_0_vlan = T.RX_L3_AC_ONE_TAG_PORT_VID
    output_ether_0_dst = T.NH_L3_AC_REG_MAC.addr_str
    output_ether_0_src = T.TX_L3_AC_REG_MAC.addr_str


class egress_tagged_test:
    egress_tagged_mode = True


class egress_untagged_test:
    egress_tagged_mode = False


class qos_pipe_mode_test:
    qos_inheritance_mode = sdk.la_mpls_qos_inheritance_mode_e_PIPE


class qos_uniform_mode_test:
    qos_inheritance_mode = sdk.la_mpls_qos_inheritance_mode_e_UNIFORM


class ipv4_rx_svi_untagged_pipe_test(
        mpls_forwarding_qos_remark_base,
        ipv4_test,
        rx_svi_test,
        egress_untagged_test,
        qos_pipe_mode_test,
        unittest.TestCase):
    pass


class ipv4_rx_svi_untagged_uniform_test(
        mpls_forwarding_qos_remark_base,
        ipv4_test,
        rx_svi_test,
        egress_untagged_test,
        qos_uniform_mode_test,
        unittest.TestCase):
    pass


class ipv4_rx_svi_tagged_pipe_test(
        mpls_forwarding_qos_remark_base,
        ipv4_test,
        rx_svi_test,
        egress_tagged_test,
        qos_pipe_mode_test,
        unittest.TestCase):
    pass


class ipv4_rx_svi_tagged_uniform_test(
        mpls_forwarding_qos_remark_base,
        ipv4_test,
        rx_svi_test,
        egress_tagged_test,
        qos_uniform_mode_test,
        unittest.TestCase):
    pass


class ipv4_rx_l3_ac_untagged_pipe_test(
        mpls_forwarding_qos_remark_base,
        ipv4_test,
        rx_l3_ac_test,
        egress_untagged_test,
        qos_pipe_mode_test,
        unittest.TestCase):
    pass


class ipv4_rx_l3_ac_untagged_uniform_test(
        mpls_forwarding_qos_remark_base,
        ipv4_test,
        rx_l3_ac_test,
        egress_untagged_test,
        qos_uniform_mode_test,
        unittest.TestCase):
    pass


class ipv4_rx_l3_ac_tagged_pipe_test(
        mpls_forwarding_qos_remark_base,
        ipv4_test,
        rx_l3_ac_test,
        egress_tagged_test,
        qos_pipe_mode_test,
        unittest.TestCase):
    pass


class ipv4_rx_l3_ac_tagged_uniform_test(
        mpls_forwarding_qos_remark_base,
        ipv4_test,
        rx_l3_ac_test,
        egress_tagged_test,
        qos_uniform_mode_test,
        unittest.TestCase):
    pass


class ipv6_rx_svi_untagged_pipe_test(
        mpls_forwarding_qos_remark_base,
        ipv6_test,
        rx_svi_test,
        egress_untagged_test,
        qos_pipe_mode_test,
        unittest.TestCase):
    pass


class ipv6_rx_svi_untagged_uniform_test(
        mpls_forwarding_qos_remark_base,
        ipv6_test,
        rx_svi_test,
        egress_untagged_test,
        qos_uniform_mode_test,
        unittest.TestCase):
    pass


class ipv6_rx_svi_tagged_pipe_test(
        mpls_forwarding_qos_remark_base,
        ipv6_test,
        rx_svi_test,
        egress_tagged_test,
        qos_pipe_mode_test,
        unittest.TestCase):
    pass


class ipv6_rx_svi_tagged_uniform_test(
        mpls_forwarding_qos_remark_base,
        ipv6_test,
        rx_svi_test,
        egress_tagged_test,
        qos_uniform_mode_test,
        unittest.TestCase):
    pass


class ipv6_rx_l3_ac_untagged_pipe_test(
        mpls_forwarding_qos_remark_base,
        ipv6_test,
        rx_l3_ac_test,
        egress_untagged_test,
        qos_pipe_mode_test,
        unittest.TestCase):
    pass


class ipv6_rx_l3_ac_untagged_uniform_test(
        mpls_forwarding_qos_remark_base,
        ipv6_test,
        rx_l3_ac_test,
        egress_untagged_test,
        qos_uniform_mode_test,
        unittest.TestCase):
    pass


class ipv6_rx_l3_ac_tagged_pipe_test(
        mpls_forwarding_qos_remark_base,
        ipv6_test,
        rx_l3_ac_test,
        egress_tagged_test,
        qos_pipe_mode_test,
        unittest.TestCase):
    pass


class ipv6_rx_l3_ac_tagged_uniform_test(
        mpls_forwarding_qos_remark_base,
        ipv6_test,
        rx_l3_ac_test,
        egress_tagged_test,
        qos_uniform_mode_test,
        unittest.TestCase):
    pass
