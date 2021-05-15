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
import unittest
from leaba import sdk
import packet_test_utils as U
from scapy.all import *
import sim_utils
import topology as T
from sdk_test_case_base import *
from packet_test_utils import *

DST_MAC = "ca:fe:ca:fe:ca:fe"
SRC_MAC = "de:ad:de:ad:de:ad"
VLAN = T.RX_L2_AC_PORT_VID1


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_qos_profile_base(sdk_test_case_base):

    # Tags
    TAG_PCPDEI = sdk.la_vlan_pcpdei()
    TAG_PCPDEI.fields.pcp = 4
    TAG_PCPDEI.fields.dei = 1

    TAG_DSCP = sdk.la_ip_dscp()
    TAG_DSCP.value = 20

    TAG_MPLS_TC = sdk.la_mpls_tc()
    TAG_MPLS_TC.value = 7

    # Forwarding headers
    OUT_FWD_PCPDEI = sdk.la_vlan_pcpdei()
    OUT_FWD_PCPDEI.fields.pcp = 3
    OUT_FWD_PCPDEI.fields.dei = 1

    OUT_FWD_DSCP = sdk.la_ip_dscp()
    OUT_FWD_DSCP.value = 30

    OUT_FWD_MPLS_TC = sdk.la_mpls_tc()
    OUT_FWD_MPLS_TC.value = 5

    EGRESS_TAG_LST = [TAG_PCPDEI, TAG_DSCP, TAG_MPLS_TC]
    INGRESS_TAG_LST = [TAG_PCPDEI, TAG_MPLS_TC]
    IP_VER_LST = [sdk.la_ip_version_e_IPV4, sdk.la_ip_version_e_IPV6]

    # Bool list
    BOOL_LST = [True, False]

    # Egress QoS fields
    # Encapsulating headers
    OUT_ENCAP_PCPDEI = sdk.la_vlan_pcpdei()
    OUT_ENCAP_PCPDEI.fields.pcp = 5
    OUT_ENCAP_PCPDEI.fields.dei = 0

    OUT_ENCAP_MPLS_TC = sdk.la_mpls_tc()
    OUT_ENCAP_MPLS_TC.value = 4

    # Encapsulating headers QoS fields'
    ENCAP_QOS_VALUES = sdk.encapsulating_headers_qos_values()
    ENCAP_QOS_VALUES.pcpdei = OUT_ENCAP_PCPDEI
    ENCAP_QOS_VALUES.tc = OUT_ENCAP_MPLS_TC

    QOS_GROUP_ID = 4
    COUNTER_OFFSET = 1

    def setUp(self):
        super().setUp()
        self.create_and_assign_qos_profiles()

    def create_and_assign_qos_profiles(self):
        # Create new ingress/egress qos profiles
        self.ingress_qos_profile_new = T.ingress_qos_profile(self, self.device)
        self.ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_enabled(True)
        self.ingress_qos_profile_new.set_default_values()
        self.egress_qos_profile_new = T.egress_qos_profile(self, self.device)
        self.egress_qos_profile_new.set_default_values()

    def create_p2p_ports(self):
        self.rx_port = self.topology.rx_l2_ac_port.hld_obj
        self.rx_port.set_ingress_qos_profile(self.ingress_qos_profile_new.hld_obj)
        self.tx_port = self.topology.tx_l2_ac_port_reg.hld_obj
        self.tx_port.set_egress_qos_profile(self.egress_qos_profile_new.hld_obj)
        self.rx_port.detach()
        self.rx_port.set_destination(self.tx_port)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_counter_offset_mapping(self):
        self.create_p2p_ports()
        self.set_counters()
        for qos in range(sdk.LA_NUM_L2_INGRESS_TRAFFIC_CLASSES):
            in_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / Dot1Q(prio=qos, id=0, vlan=VLAN)
            out_packet_base = Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / Dot1Q(prio=qos, id=0, vlan=VLAN)
            in_packet, out_packet = pad_input_and_output_packets(in_packet_base, out_packet_base)

            run_and_compare(
                self,
                self.device,
                in_packet,
                T.RX_SLICE,
                T.RX_IFG,
                T.FIRST_SERDES,
                out_packet,
                T.TX_SLICE_REG,
                T.TX_IFG_REG,
                T.FIRST_SERDES_SVI_REG)

            for offset in range(sdk.LA_NUM_L2_INGRESS_TRAFFIC_CLASSES):
                if offset == qos:
                    expected = 1
                else:
                    expected = 0

                packet_count, byte_count = self.ingress_counter.read(offset, True, True)
                self.assertEqual(packet_count, expected)

                packet_count, byte_count = self.egress_counter.read(offset, True, True)
                self.assertEqual(packet_count, expected)

    def set_counters(self):
        self.ingress_counter = self.device.create_counter(sdk.LA_NUM_L2_INGRESS_TRAFFIC_CLASSES)
        self.rx_port.set_ingress_counter(sdk.la_counter_set.type_e_QOS, self.ingress_counter)
        self.egress_counter = self.device.create_counter(sdk.LA_NUM_EGRESS_TRAFFIC_CLASSES)
        self.tx_port.set_egress_counter(sdk.la_counter_set.type_e_QOS, self.egress_counter)

        pcpdei = sdk.la_vlan_pcpdei()
        for pcp in range(0, 8):
            for dei in range(0, 2):
                pcpdei.fields.pcp = pcp
                pcpdei.fields.dei = dei
                self.ingress_qos_profile_new.hld_obj.set_meter_or_counter_offset_mapping(pcpdei, pcp)
                self.egress_qos_profile_new.hld_obj.set_counter_offset_mapping(pcpdei, pcp)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_counter_offset_mapping_getters(self):
        # Counter offsets
        COUNTER_OFFSET_LST = [1, 2, 3]
        INVALI_COUNTER_OFFSET = 8

        # Check set/get Counter offsets mappings based on FORWARDING_HEADER and tags.
        for tag in self.EGRESS_TAG_LST:
            for offset in COUNTER_OFFSET_LST:

                self.egress_qos_profile_new.hld_obj.set_counter_offset_mapping(tag, offset)

                res_offset = self.egress_qos_profile_new.hld_obj.get_counter_offset_mapping(tag)
                self.assertEqual(res_offset, offset)

            try:
                self.egress_qos_profile_new.hld_obj.set_counter_offset_mapping(tag, INVALI_COUNTER_OFFSET)
                self.assertFail()
            except BaseException:
                pass

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_counter_offset_mapping_getters_qos_group(self):
        self.egress_qos_profile_new.hld_obj.set_counter_offset_mapping(self.QOS_GROUP_ID, self.COUNTER_OFFSET)
        res_offset = self.egress_qos_profile_new.hld_obj.get_counter_offset_mapping(self.QOS_GROUP_ID)
        self.assertEqual(res_offset, self.COUNTER_OFFSET)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_qos_tag_mapping_dscp_getters(self):
        # Check set/get forwarding and encapsulating headers QoS fields' based on dscp tags.
        res_out_fwd_dscp = sdk.la_ip_dscp()

        self.egress_qos_profile_new.hld_obj.set_qos_tag_mapping_dscp(self.TAG_DSCP, self.OUT_FWD_DSCP, self.ENCAP_QOS_VALUES)
        (res_out_fwd_dscp, res_encap_qos_values) = self.egress_qos_profile_new.hld_obj.get_qos_tag_mapping_dscp(self.TAG_DSCP)
        self.assertEqual(res_out_fwd_dscp.value, self.OUT_FWD_DSCP.value)
        self.assertEqual(res_encap_qos_values.pcpdei.flat, self.ENCAP_QOS_VALUES.pcpdei.flat)
        self.assertEqual(res_encap_qos_values.tos.flat, self.ENCAP_QOS_VALUES.tos.flat)
        self.assertEqual(res_encap_qos_values.tc.value, self.ENCAP_QOS_VALUES.tc.value)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_qos_tag_mapping_mpls_getters(self):
        # Check set/get forwarding and encapsulating headers QoS fields' based on mpls_tc tags.
        res_out_fwd_mpls = sdk.la_mpls_tc()

        self.egress_qos_profile_new.hld_obj.set_qos_tag_mapping_mpls_tc(
            self.TAG_MPLS_TC, self.OUT_FWD_MPLS_TC, self.ENCAP_QOS_VALUES)
        (res_out_fwd_mpls, res_encap_qos_values) = self.egress_qos_profile_new.hld_obj.get_qos_tag_mapping_mpls_tc(self.TAG_MPLS_TC)
        self.assertEqual(res_encap_qos_values.pcpdei.flat, self.ENCAP_QOS_VALUES.pcpdei.flat)
        self.assertEqual(res_encap_qos_values.tos.flat, self.ENCAP_QOS_VALUES.tos.flat)
        self.assertEqual(res_encap_qos_values.tc.value, self.ENCAP_QOS_VALUES.tc.value)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_egress_qos_tag_mapping_pcpdei_getters(self):
        # Check set/get forwarding and encapsulating headers QoS fields' based on pcpdei tags.
        self.egress_qos_profile_new.hld_obj.set_qos_tag_mapping_pcpdei(self.TAG_PCPDEI, self.OUT_FWD_PCPDEI, self.ENCAP_QOS_VALUES)
        (res_fwd_pcpdei, res_encap_qos_values) = self.egress_qos_profile_new.hld_obj.get_qos_tag_mapping_pcpdei(self.TAG_PCPDEI)
        self.assertEqual(res_fwd_pcpdei.flat, self.OUT_FWD_PCPDEI.flat)
        self.assertEqual(res_encap_qos_values.tos.flat, self.ENCAP_QOS_VALUES.tos.flat)
        self.assertEqual(res_encap_qos_values.tc.value, self.ENCAP_QOS_VALUES.tc.value)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ingress_color_mapping_getters(self):
        # Colors
        COLOR_LST = [sdk.la_qos_color_e_GREEN, sdk.la_qos_color_e_YELLOW, sdk.la_qos_color_e_RED]

        # Check set/get color mappings based on tags.
        for color in COLOR_LST:
            for tag in self.INGRESS_TAG_LST:
                self.ingress_qos_profile_new.hld_obj.set_color_mapping(tag, color)
                res_color = self.ingress_qos_profile_new.hld_obj.get_color_mapping(tag)
                self.assertEqual(res_color, color)
            for ip_ver in self.IP_VER_LST:
                self.ingress_qos_profile_new.hld_obj.set_color_mapping(ip_ver, self.TAG_DSCP, color)
                res_color = self.ingress_qos_profile_new.hld_obj.get_color_mapping(ip_ver, self.TAG_DSCP)
                self.assertEqual(res_color, color)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ingress_encap_qos_tag_mapping_getters(self):
        # Encapsulation mpls traffic-class
        ENCAP_MPLS_TC_LST = [1, 3]

        # Check set/get encap qos tag mappings based on FORWARDING_HEADER and tags.
        encap_mpls_tc = sdk.la_mpls_tc()
        for encap_mpls_tc.value in ENCAP_MPLS_TC_LST:
            for tag in self.INGRESS_TAG_LST:
                self.ingress_qos_profile_new.hld_obj.set_encap_qos_tag_mapping(tag, encap_mpls_tc)
                res_encap_mpls_tc = self.ingress_qos_profile_new.hld_obj.get_encap_qos_tag_mapping(tag)
                self.assertEqual(res_encap_mpls_tc.value, encap_mpls_tc.value)

                try:
                    self.ingress_qos_profile_new.hld_obj.set_encap_qos_tag_mapping(tag, INVALID_ENCAP_QOS_TAG)
                    self.assertFail()
                except BaseException:
                    pass
            for ip_ver in self.IP_VER_LST:
                self.ingress_qos_profile_new.hld_obj.set_encap_qos_tag_mapping(ip_ver, self.TAG_DSCP, encap_mpls_tc)
                res_encap_mpls_tc = self.ingress_qos_profile_new.hld_obj.get_encap_qos_tag_mapping(ip_ver, self.TAG_DSCP)
                self.assertEqual(res_encap_mpls_tc.value, encap_mpls_tc.value)

                try:
                    self.ingress_qos_profile_new.hld_obj.set_encap_qos_tag_mapping(ip_ver, self.TAG_DSCP, INVALID_ENCAP_QOS_TAG)
                    self.assertFail()
                except BaseException:
                    pass

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ingress_metering_enabled_mapping_getters(self):
        # Check set/get metering enablement based on FORWARDING_HEADER and tags.

        for is_enabled in self.BOOL_LST:
            for tag in self.INGRESS_TAG_LST:
                self.ingress_qos_profile_new.hld_obj.set_metering_enabled_mapping(tag, is_enabled)
                res_is_enabled = self.ingress_qos_profile_new.hld_obj.get_metering_enabled_mapping(tag)
                self.assertEqual(res_is_enabled, is_enabled)
            for ip_ver in self.IP_VER_LST:
                self.ingress_qos_profile_new.hld_obj.set_metering_enabled_mapping(ip_ver, self.TAG_DSCP, is_enabled)
                res_is_enabled = self.ingress_qos_profile_new.hld_obj.get_metering_enabled_mapping(ip_ver, self.TAG_DSCP)
                self.assertEqual(res_is_enabled, is_enabled)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ingress_qos_tag_mapping_dscp_getters(self):
        # Check set/get forwarding and encapsulating headers QoS fields' based on dscp tags.
        res_out_ip_dscp = sdk.la_ip_dscp()

        for ip_ver in self.IP_VER_LST:
            self.ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_dscp(ip_ver, self.TAG_DSCP, self.OUT_FWD_DSCP)
            res_out_ip_dscp = self.ingress_qos_profile_new.hld_obj.get_qos_tag_mapping_dscp(ip_ver, self.TAG_DSCP)
            self.assertEqual(res_out_ip_dscp.value, self.OUT_FWD_DSCP.value)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ingress_qos_tag_mapping_mpls_getters(self):
        # Check set/get forwarding and encapsulating headers QoS fields' based on mpls_tc tags.
        res_out_fwd_mpls = sdk.la_mpls_tc()

        self.ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_mpls_tc(self.TAG_MPLS_TC, self.OUT_FWD_MPLS_TC)
        res_out_fwd_mpls = self.ingress_qos_profile_new.hld_obj.get_qos_tag_mapping_mpls_tc(self.TAG_MPLS_TC)
        self.assertEqual(res_out_fwd_mpls.value, self.OUT_FWD_MPLS_TC.value)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ingress_qos_tag_mapping_pcpdei_getters(self):
        # Check set/get forwarding and encapsulating headers QoS fields' based on pcpdei tags.
        res_out_pcpdei = sdk.la_vlan_pcpdei()

        self.ingress_qos_profile_new.hld_obj.set_qos_tag_mapping_pcpdei(self.TAG_PCPDEI, self.OUT_FWD_PCPDEI)
        res_out_pcpdei = self.ingress_qos_profile_new.hld_obj.get_qos_tag_mapping_pcpdei(self.TAG_PCPDEI)
        self.assertEqual(res_out_pcpdei.flat, self.OUT_FWD_PCPDEI.flat)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ingress_traffic_class_mapping_getters(self):
        # Traffic classes
        TC_LST = [1, 2, 3]
        INVALID_TC = 200

        # Check set/get traffic_classes mappings based on FORWARDING_HEADER and tags.
        for tag in self.INGRESS_TAG_LST:
            for tc in TC_LST:
                self.ingress_qos_profile_new.hld_obj.set_traffic_class_mapping(tag, tc)
                res_tc = self.ingress_qos_profile_new.hld_obj.get_traffic_class_mapping(tag)
                self.assertEqual(res_tc, tc)

            try:
                self.ingress_qos_profile_new.hld_obj.set_traffic_class_mapping(tag, INVALID_TC)
                self.assertFail()
            except BaseException:
                pass

        for ip_ver in self.IP_VER_LST:
            for tc in TC_LST:
                self.ingress_qos_profile_new.hld_obj.set_traffic_class_mapping(ip_ver, self.TAG_DSCP, tc)
                res_tc = self.ingress_qos_profile_new.hld_obj.get_traffic_class_mapping(ip_ver, self.TAG_DSCP)
                self.assertEqual(res_tc, tc)

            try:
                self.ingress_qos_profile_new.hld_obj.set_traffic_class_mapping(ip_ver, self.TAG_DSCP, INVALID_TC)
                self.assertFail()
            except BaseException:
                pass


if __name__ == '__main__':
    unittest.main()
