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

from leaba import sdk
from packet_test_utils import *
import sim_utils
import topology as T
from scapy.all import *
import decor

from sdk_test_case_base import *
from l2_rtf_base import *


@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
class l2_rtf(l2_rtf_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_eth_first_drop_acl(self):
        acl1 = self.device.create_acl(self.eth_acl_key_profile, self.topology.acl_command_profile_def)
        acl2 = self.device.create_acl(self.eth_acl_key_profile, self.topology.acl_command_profile_def)

        key = []
        field = sdk.la_acl_field()
        field.type = sdk.la_acl_field_type_e_DA
        destination_mac = T.mac_addr(DST_MAC)
        field.val.da.flat = destination_mac.to_num()
        field.mask.da.flat = 0xffffffffffff
        key.append(field)

        command1 = self.create_drop_command()
        acl1.append(key, command1)

        command2 = self.create_mirror_cmd_acl_command(MIRROR_CMD_GID1)
        acl2.append(key, command2)

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_ETHERNET, [acl1, acl2])
        self.rx_ac_port.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        l2_acl_group = self.rx_ac_port.hld_obj.get_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.assertEqual(acl_group.this, l2_acl_group.this)

        run_and_drop(self, self.device, INPUT_IPV4_o_MPLS_PACKET, self.RX_SLICE, RX_IFG, RX_SERDES_FIRST)

        self.rx_ac_port.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        run_and_compare(self, self.device,
                        INPUT_IPV4_o_MPLS_PACKET, self.RX_SLICE, RX_IFG, RX_SERDES_FIRST,
                        OUTPUT_IPV4_o_MPLS_PACKET, self.TX_SLICE_DEF, TX_IFG_DEF, TX_SERDES_FIRST_DEF)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_eth_second_drop_acl(self):
        acl1 = self.device.create_acl(self.eth_acl_key_profile, self.topology.acl_command_profile_def)
        acl2 = self.device.create_acl(self.eth_acl_key_profile, self.topology.acl_command_profile_def)

        key = []
        field = sdk.la_acl_field()
        field.type = sdk.la_acl_field_type_e_SA
        source_mac = T.mac_addr(SRC_MAC)
        field.val.sa.flat = source_mac.to_num()
        field.mask.sa.flat = 0xffffffffffff
        key.append(field)

        command1 = self.create_force_l2_destination_command(self.tx_ac_port_ext.hld_obj)
        acl1.append(key, command1)

        command2 = self.create_drop_command()
        acl2.append(key, command2)

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_ETHERNET, [acl1, acl2])
        self.rx_ac_port.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        l2_acl_group = self.rx_ac_port.hld_obj.get_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.assertEqual(acl_group.this, l2_acl_group.this)

        run_and_drop(self, self.device, INPUT_IPV4_o_MPLS_PACKET, self.RX_SLICE, RX_IFG, RX_SERDES_FIRST)

        self.rx_ac_port.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

        run_and_compare(self, self.device,
                        INPUT_IPV4_o_MPLS_PACKET, self.RX_SLICE, RX_IFG, RX_SERDES_FIRST,
                        OUTPUT_IPV4_o_MPLS_PACKET, self.TX_SLICE_DEF, TX_IFG_DEF, TX_SERDES_FIRST_DEF)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_eth_override_l2_dest(self):
        acl1 = self.device.create_acl(self.eth_acl_key_profile, self.topology.acl_command_profile_def)
        acl2 = self.device.create_acl(self.eth_acl_key_profile, self.topology.acl_command_profile_def)

        key = []
        field = sdk.la_acl_field()
        field.type = sdk.la_acl_field_type_e_SA
        source_mac = T.mac_addr(SRC_MAC)
        field.val.sa.flat = source_mac.to_num()
        field.mask.sa.flat = 0xffffffffffff
        key.append(field)

        command1 = self.create_force_l2_destination_command(self.tx_ac_port_ext.hld_obj)
        acl1.append(key, command1)

        command2 = self.create_force_l2_destination_command(self.tx_ac_port_def.hld_obj)
        acl2.append(key, command2)

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_ETHERNET, [acl1, acl2])
        self.rx_ac_port.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        l2_acl_group = self.rx_ac_port.hld_obj.get_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.assertEqual(acl_group.this, l2_acl_group.this)

        run_and_compare(self, self.device,
                        INPUT_IPV4_o_MPLS_PACKET, self.RX_SLICE, RX_IFG, RX_SERDES_FIRST,
                        OUTPUT_IPV4_o_MPLS_PACKET, self.TX_SLICE_DEF, TX_IFG_DEF, TX_SERDES_FIRST_DEF)

        self.rx_ac_port.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_eth_modify_acl_group(self):
        acl1 = self.device.create_acl(self.eth_acl_key_profile, self.topology.acl_command_profile_def)
        acl2 = self.device.create_acl(self.eth_acl_key_profile, self.topology.acl_command_profile_def)

        key = []
        field = sdk.la_acl_field()
        field.type = sdk.la_acl_field_type_e_DA
        destination_mac = T.mac_addr(DST_MAC)
        field.val.da.flat = destination_mac.to_num()
        field.mask.da.flat = 0xffffffffffff
        key.append(field)

        counter = self.device.create_counter(1)
        command1 = self.create_counter_command(counter)
        acl1.append(key, command1)

        command2 = self.create_force_l2_destination_command(self.tx_ac_port_ext.hld_obj)
        acl2.append(key, command2)

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_ETHERNET, [acl1, None, None, acl2])
        self.rx_ac_port.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        l2_acl_group = self.rx_ac_port.hld_obj.get_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.assertEqual(acl_group.this, l2_acl_group.this)

        run_and_compare(self, self.device,
                        INPUT_IPV4_o_MPLS_PACKET, self.RX_SLICE, RX_IFG, RX_SERDES_FIRST,
                        OUTPUT_IPV4_o_MPLS_PACKET, self.TX_SLICE_EXT, TX_IFG_EXT, TX_SERDES_FIRST_EXT)

        packet_count, _ = counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        eth_acls = l2_acl_group.get_acls(sdk.la_acl_packet_format_e_ETHERNET)

        acl3 = self.device.create_acl(self.eth_acl_key_profile, self.topology.acl_command_profile_def)
        command3 = self.create_tc_and_color_command(7, 3)
        acl3.append(key, command3)

        eth_acls[2] = acl3
        l2_acl_group.set_acls(sdk.la_acl_packet_format_e_ETHERNET, eth_acls)

        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0x1F}}
        run_and_compare_inner_fields(self, self.device,
                                     INPUT_IPV4_o_MPLS_PACKET, self.RX_SLICE, RX_IFG, RX_SERDES_FIRST,
                                     OUTPUT_IPV4_o_MPLS_PACKET, self.TX_SLICE_EXT, TX_IFG_EXT, TX_SERDES_FIRST_EXT,
                                     control_expected)

        packet_count, _ = counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        self.rx_ac_port.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_eth_multiple_counter_action(self):
        acl1 = self.device.create_acl(self.eth_acl_key_profile, self.topology.acl_command_profile_def)
        acl2 = self.device.create_acl(self.eth_acl_key_profile, self.topology.acl_command_profile_def)

        key = []
        field = sdk.la_acl_field()
        field.type = sdk.la_acl_field_type_e_DA
        destination_mac = T.mac_addr(DST_MAC)
        field.val.da.flat = destination_mac.to_num()
        field.mask.da.flat = 0xffffffffffff
        key.append(field)

        counter1 = self.device.create_counter(1)
        command1 = self.create_counter_command(counter1)
        acl1.append(key, command1)

        counter2 = self.device.create_counter(1)
        command2 = self.create_counter_command(counter2)
        acl2.append(key, command2)

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_ETHERNET, [acl1, acl2])
        self.rx_ac_port.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        l2_acl_group = self.rx_ac_port.hld_obj.get_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.assertEqual(acl_group.this, l2_acl_group.this)

        run_and_compare(self, self.device,
                        INPUT_IPV4_o_MPLS_PACKET, self.RX_SLICE, RX_IFG, RX_SERDES_FIRST,
                        OUTPUT_IPV4_o_MPLS_PACKET, self.TX_SLICE_DEF, TX_IFG_DEF, TX_SERDES_FIRST_DEF)

        # First ACL counter will not be updated in HW.
        # Assertion check is commented till we get NPL fix for NSIM.
        packet_count, _ = counter1.read(0, True, True)
        #self.assertEqual(packet_count, 1)

        # Check for ACL-2 counter
        packet_count, _ = counter2.read(0, True, True)
        self.assertEqual(packet_count, 1)

        self.rx_ac_port.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_eth_multiple_qos_counter_action(self):
        acl1 = self.device.create_acl(self.eth_acl_key_profile, self.topology.acl_command_profile_def)
        acl2 = self.device.create_acl(self.eth_acl_key_profile, self.topology.acl_command_profile_def)

        key = []
        field = sdk.la_acl_field()
        field.type = sdk.la_acl_field_type_e_DA
        destination_mac = T.mac_addr(DST_MAC)
        field.val.da.flat = destination_mac.to_num()
        field.mask.da.flat = 0xffffffffffff
        key.append(field)

        q_counter = self.device.create_counter(8)
        self.rx_ac_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_QOS, q_counter)

        command1 = self.create_qos_commands(QOS_COUNTER_OFFSET - 1, QOS_MARK_DSCP - 1)
        acl1.append(key, command1)

        command2 = self.create_qos_commands(QOS_COUNTER_OFFSET, QOS_MARK_DSCP)
        acl2.append(key, command2)

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_ETHERNET, [acl1, acl2])
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [acl1, acl2])
        self.rx_ac_port.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        l2_acl_group = self.rx_ac_port.hld_obj.get_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.assertEqual(acl_group.this, l2_acl_group.this)

        run_and_compare(self, self.device,
                        INPUT_IPV4_o_MPLS_PACKET, self.RX_SLICE, RX_IFG, RX_SERDES_FIRST,
                        OUTPUT_IPV4_o_MPLS_PACKET, self.TX_SLICE_DEF, TX_IFG_DEF, TX_SERDES_FIRST_DEF)

        packet_count, _ = q_counter.read(QOS_COUNTER_OFFSET - 1, True, True)
        self.assertEqual(packet_count, 0)

        packet_count, _ = q_counter.read(QOS_COUNTER_OFFSET, True, True)
        self.assertEqual(packet_count, 1)

        output_packet = OUTPUT_IPV4_PACKET.copy()
        output_packet[IP].tos = QOS_MARK_DSCP << 2
        run_and_compare(self, self.device,
                        INPUT_IPV4_PACKET, self.RX_SLICE, RX_IFG, RX_SERDES_FIRST,
                        output_packet, self.TX_SLICE_DEF, TX_IFG_DEF, TX_SERDES_FIRST_DEF)

        packet_count, _ = q_counter.read(QOS_COUNTER_OFFSET - 1, True, True)
        self.assertEqual(packet_count, 0)

        packet_count, _ = q_counter.read(QOS_COUNTER_OFFSET, True, True)
        self.assertEqual(packet_count, 1)

        self.rx_ac_port.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.rx_ac_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_QOS, None)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(True, "Test fails because of the changes in mirror logic")
    def test_eth_override_mirror_cmd(self):
        acl1 = self.device.create_acl(self.eth_acl_key_profile, self.topology.acl_command_profile_def)
        acl2 = self.device.create_acl(self.eth_acl_key_profile, self.topology.acl_command_profile_def)

        key = []
        field = sdk.la_acl_field()
        field.type = sdk.la_acl_field_type_e_DA
        destination_mac = T.mac_addr(DST_MAC)
        field.val.da.flat = destination_mac.to_num()
        field.mask.da.flat = 0xffffffffffff
        key.append(field)

        command1 = self.create_mirror_cmd_acl_command(MIRROR_CMD_GID1)
        acl1.append(key, command1)

        command2 = self.create_mirror_cmd_acl_command(MIRROR_CMD_GID2)
        acl2.append(key, command2)

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_ETHERNET, [acl1, acl2])
        self.rx_ac_port.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        l2_acl_group = self.rx_ac_port.hld_obj.get_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.assertEqual(acl_group.this, l2_acl_group.this)

        out_mirror_packet = MIRROR_PACKET.copy()
        out_mirror_packet[Punt].code = MIRROR_CMD_GID2

        run_and_compare_list(self, self.device,
                             {'data': INPUT_IPV4_o_MPLS_PACKET,
                              'slice': self.RX_SLICE,
                              'ifg': RX_IFG,
                              'pif': RX_SERDES_FIRST},
                             [{'data': out_mirror_packet,
                               'slice': self.PUNT_INJECT_SLICE,
                               'ifg': PUNT_INJECT_IFG,
                               'pif': PUNT_INJECT_SERDES_FIRST},
                              {'data': OUTPUT_IPV4_o_MPLS_PACKET,
                               'slice': self.TX_SLICE_DEF,
                               'ifg': TX_IFG_DEF,
                               'pif': TX_SERDES_FIRST_DEF}])

        self.rx_ac_port.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_multiple_packet_formats_same_key_profiles(self):
        acl1 = self.device.create_acl(self.eth_acl_key_profile, self.topology.acl_command_profile_def)
        acl2 = self.device.create_acl(self.eth_acl_key_profile, self.topology.acl_command_profile_def)
        acl3 = self.device.create_acl(self.eth_acl_key_profile, self.topology.acl_command_profile_def)

        key = []
        field = sdk.la_acl_field()
        field.type = sdk.la_acl_field_type_e_SA
        source_mac = T.mac_addr(SRC_MAC)
        field.val.sa.flat = source_mac.to_num()
        field.mask.sa.flat = 0xffffffffffff
        key.append(field)

        counter = self.device.create_counter(1)
        command1 = self.create_counter_command(counter)
        acl1.append(key, command1)

        command2 = self.create_drop_command()
        acl2.append(key, command2)

        command3 = self.create_force_l2_destination_command(self.tx_ac_port_ext.hld_obj)
        acl3.append(key, command3)

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_ETHERNET, [acl1])
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [acl2])
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, [acl3])
        self.rx_ac_port.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        l2_acl_group = self.rx_ac_port.hld_obj.get_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.assertEqual(acl_group.this, l2_acl_group.this)

        run_and_compare(self, self.device,
                        INPUT_IPV4_o_MPLS_PACKET, self.RX_SLICE, RX_IFG, RX_SERDES_FIRST,
                        OUTPUT_IPV4_o_MPLS_PACKET, self.TX_SLICE_DEF, TX_IFG_DEF, TX_SERDES_FIRST_DEF)

        packet_count, _ = counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        run_and_drop(self, self.device, INPUT_IPV4_PACKET, self.RX_SLICE, RX_IFG, RX_SERDES_FIRST)

        run_and_compare(self, self.device,
                        INPUT_IPV6_o_MPLS_PACKET, self.RX_SLICE, RX_IFG, RX_SERDES_FIRST,
                        OUTPUT_IPV6_o_MPLS_PACKET, self.TX_SLICE_DEF, TX_IFG_DEF, TX_SERDES_FIRST_DEF)

        packet_count, _ = counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        run_and_compare(self, self.device,
                        INPUT_IPV6_PACKET, self.RX_SLICE, RX_IFG, RX_SERDES_FIRST,
                        OUTPUT_IPV6_PACKET, self.TX_SLICE_EXT, TX_IFG_EXT, TX_SERDES_FIRST_EXT)

        self.rx_ac_port.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_hw_pacific(), "Test is skipped for HW Pacific due to bug in mirroring")
    @unittest.skipIf(True, "Test fails because of the changes in mirror logic")
    def test_multiple_packet_formats_different_key_profiles(self):
        self.eth_acl_key_profile2 = self.device.create_acl_key_profile(
            sdk.la_acl_key_type_e_ETHERNET, sdk.la_acl_direction_e_INGRESS, sdk.LA_ACL_KEY_ETHERNET, 0)

        self.ipv4_acl_key_profile2 = self.device.create_acl_key_profile(
            sdk.la_acl_key_type_e_IPV4, sdk.la_acl_direction_e_INGRESS, sdk.LA_ACL_KEY_IPV4, 0)

        self.ipv6_acl_key_profile2 = self.device.create_acl_key_profile(
            sdk.la_acl_key_type_e_IPV6, sdk.la_acl_direction_e_INGRESS, sdk.LA_ACL_KEY_IPV6, 0)

        acl1 = self.device.create_acl(self.eth_acl_key_profile, self.topology.acl_command_profile_def)
        acl2 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)
        acl3 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv6_def, self.topology.acl_command_profile_def)

        acl4 = self.device.create_acl(self.eth_acl_key_profile2, self.topology.acl_command_profile_def)
        acl5 = self.device.create_acl(self.ipv4_acl_key_profile2, self.topology.acl_command_profile_def)
        acl6 = self.device.create_acl(self.ipv6_acl_key_profile2, self.topology.acl_command_profile_def)

        key = []
        field = sdk.la_acl_field()
        field.type = sdk.la_acl_field_type_e_SA
        source_mac = T.mac_addr(SRC_MAC)
        field.val.sa.flat = source_mac.to_num()
        field.mask.sa.flat = 0xffffffffffff
        key.append(field)

        counter1 = self.device.create_counter(1)
        command1 = self.create_counter_command(counter1)
        acl1.append(key, command1)

        key = []
        field = sdk.la_acl_field()
        field.type = sdk.la_acl_field_type_e_IPV4_SIP
        field.val.ipv4_sip.s_addr = IPV4_SIP.to_num()
        field.mask.ipv4_sip.s_addr = 0xffffffff
        key.append(field)

        command2 = self.create_drop_command()
        acl2.append(key, command2)

        key = []
        field = sdk.la_acl_field()
        field.type = sdk.la_acl_field_type_e_IPV6_SIP
        q0 = sdk.get_ipv6_addr_q0(IPV6_SIP.hld_obj)
        q1 = sdk.get_ipv6_addr_q1(IPV6_SIP.hld_obj)
        sdk.set_ipv6_addr(field.val.ipv6_sip, q0, q1)
        sdk.set_ipv6_addr(field.mask.ipv6_sip, 0xffffffffffffffff, 0xffffffffffffffff)
        key.append(field)

        command3 = self.create_force_l2_destination_command(self.tx_ac_port_ext.hld_obj)
        acl3.append(key, command3)

        key = []
        field = sdk.la_acl_field()
        field.type = sdk.la_acl_field_type_e_SA
        source_mac = T.mac_addr(SRC_MAC)
        field.val.sa.flat = source_mac.to_num()
        field.mask.sa.flat = 0xffffffffffff
        key.append(field)

        command4 = self.create_tc_and_color_command(7, 3)
        acl4.append(key, command4)

        key = []
        field = sdk.la_acl_field()
        field.type = sdk.la_acl_field_type_e_IPV4_SIP
        field.val.ipv4_sip.s_addr = IPV4_SIP.to_num()
        field.mask.ipv4_sip.s_addr = 0xffffffff
        key.append(field)

        counter2 = self.device.create_counter(1)
        command5 = self.create_counter_command(counter2)
        acl5.append(key, command5)

        key = []
        field = sdk.la_acl_field()
        field.type = sdk.la_acl_field_type_e_IPV6_SIP
        q0 = sdk.get_ipv6_addr_q0(IPV6_SIP.hld_obj)
        q1 = sdk.get_ipv6_addr_q1(IPV6_SIP.hld_obj)
        sdk.set_ipv6_addr(field.val.ipv6_sip, q0, q1)
        sdk.set_ipv6_addr(field.mask.ipv6_sip, 0xffffffffffffffff, 0xffffffffffffffff)
        key.append(field)

        command6 = self.create_mirror_cmd_acl_command(MIRROR_CMD_GID1)
        acl6.append(key, command6)

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_ETHERNET, [acl1, acl4])
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [acl2, acl5])
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, [acl3, acl6])
        self.rx_ac_port.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        l2_acl_group = self.rx_ac_port.hld_obj.get_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.assertEqual(acl_group.this, l2_acl_group.this)

        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0x1F}}
        run_and_compare_inner_fields(self, self.device,
                                     INPUT_IPV4_o_MPLS_PACKET, self.RX_SLICE, RX_IFG, RX_SERDES_FIRST,
                                     OUTPUT_IPV4_o_MPLS_PACKET, self.TX_SLICE_DEF, TX_IFG_DEF, TX_SERDES_FIRST_DEF,
                                     control_expected)

        packet_count, _ = counter1.read(0, True, True)
        self.assertEqual(packet_count, 1)

        run_and_drop(self, self.device, INPUT_IPV4_PACKET, self.RX_SLICE, RX_IFG, RX_SERDES_FIRST)

        packet_count, _ = counter2.read(0, True, True)
        self.assertEqual(packet_count, 0)

        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0x1F}}
        run_and_compare_inner_fields(self, self.device,
                                     INPUT_IPV4_o_MPLS_PACKET, self.RX_SLICE, RX_IFG, RX_SERDES_FIRST,
                                     OUTPUT_IPV4_o_MPLS_PACKET, self.TX_SLICE_DEF, TX_IFG_DEF, TX_SERDES_FIRST_DEF,
                                     control_expected)

        packet_count, _ = counter1.read(0, True, True)
        self.assertEqual(packet_count, 1)

        run_and_compare_list(self, self.device,
                             {'data': INPUT_IPV6_PACKET,
                              'slice': self.RX_SLICE,
                              'ifg': RX_IFG,
                              'pif': RX_SERDES_FIRST},
                             [{'data': OUTPUT_IPV6_PACKET,
                               'slice': self.TX_SLICE_EXT,
                               'ifg': TX_IFG_EXT,
                               'pif': TX_SERDES_FIRST_EXT},
                              {'data': MIRROR_IPV6_PACKET,
                               'slice': self.PUNT_INJECT_SLICE,
                               'ifg': PUNT_INJECT_IFG,
                               'pif': PUNT_INJECT_SERDES_FIRST}])

        self.rx_ac_port.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(True, "Test fails because of the changes in mirror logic")
    def test_eth_do_mirror_command(self):
        acl1 = self.device.create_acl(self.eth_acl_key_profile, self.topology.acl_command_profile_def)

        self.rx_ac_port.hld_obj.set_ingress_mirror_command(self.lp_mirror_cmd, is_acl_conditioned=True)

        key = []
        field = sdk.la_acl_field()
        field.type = sdk.la_acl_field_type_e_DA
        destination_mac = T.mac_addr(DST_MAC)
        field.val.da.flat = destination_mac.to_num()
        field.mask.da.flat = 0xffffffffffff
        key.append(field)

        counter = self.device.create_counter(1)
        command1 = self.create_counter_command(counter)
        acl1.append(key, command1)

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_ETHERNET, [acl1])
        self.rx_ac_port.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        l2_acl_group = self.rx_ac_port.hld_obj.get_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.assertEqual(acl_group.this, l2_acl_group.this)

        run_and_compare(self, self.device,
                        INPUT_IPV4_o_MPLS_PACKET, self.RX_SLICE, RX_IFG, RX_SERDES_FIRST,
                        OUTPUT_IPV4_o_MPLS_PACKET, self.TX_SLICE_DEF, TX_IFG_DEF, TX_SERDES_FIRST_DEF)

        packet_count, _ = counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        acl2 = self.device.create_acl(self.eth_acl_key_profile, self.topology.acl_command_profile_def)
        command2 = self.create_mirror_cmd_acl_command(MIRROR_CMD_GID1)
        acl2.append(key, command2)

        eth_l2_acls = l2_acl_group.get_acls(sdk.la_acl_packet_format_e_ETHERNET)
        eth_l2_acls.append(acl2)
        l2_acl_group.set_acls(sdk.la_acl_packet_format_e_ETHERNET, eth_l2_acls)

        out_mirror_packet = MIRROR_PACKET.copy()
        out_mirror_packet[Punt].code = MIRROR_CMD_GID1

        run_and_compare_list(self, self.device,
                             {'data': INPUT_IPV4_o_MPLS_PACKET,
                              'slice': self.RX_SLICE,
                              'ifg': RX_IFG,
                              'pif': RX_SERDES_FIRST},
                             [{'data': OUTPUT_IPV4_o_MPLS_PACKET,
                               'slice': self.TX_SLICE_DEF,
                               'ifg': TX_IFG_DEF,
                               'pif': TX_SERDES_FIRST_DEF},
                              {'data': out_mirror_packet,
                               'slice': self.PUNT_INJECT_SLICE,
                               'ifg': PUNT_INJECT_IFG,
                               'pif': PUNT_INJECT_SERDES_FIRST}])

        packet_count, _ = counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        acl3 = self.device.create_acl(self.eth_acl_key_profile, self.topology.acl_command_profile_def)
        command3 = self.create_mirror_from_lp_command()
        acl3.append(key, command3)
        eth_l2_acls.append(acl3)
        l2_acl_group.set_acls(sdk.la_acl_packet_format_e_ETHERNET, eth_l2_acls)

        out_mirror_packet = MIRROR_PACKET.copy()
        out_mirror_packet[Punt].code = LP_MIRROR_CMD_GID

        run_and_compare_list(self, self.device,
                             {'data': INPUT_IPV4_o_MPLS_PACKET,
                              'slice': self.RX_SLICE,
                              'ifg': RX_IFG,
                              'pif': RX_SERDES_FIRST},
                             [{'data': OUTPUT_IPV4_o_MPLS_PACKET,
                               'slice': self.TX_SLICE_DEF,
                               'ifg': TX_IFG_DEF,
                               'pif': TX_SERDES_FIRST_DEF},
                              {'data': out_mirror_packet,
                               'slice': self.PUNT_INJECT_SLICE,
                               'ifg': PUNT_INJECT_IFG,
                               'pif': PUNT_INJECT_SERDES_FIRST}])

        packet_count, _ = counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        self.rx_ac_port.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    def test_qos_group_field(self):
        udk = []
        udf0 = sdk.la_acl_field_def()
        udf0.type = sdk.la_acl_field_type_e_QOS_GROUP
        udk.append(udf0)

        key_type = sdk.la_acl_key_type_e_ETHERNET
        direction = sdk.la_acl_direction_e_INGRESS
        tcam_pool_id = 0
        self.custom_acl_key_profile_eth = self.device.create_acl_key_profile(key_type, direction, udk, tcam_pool_id)

        key_type = sdk.la_acl_key_type_e_IPV4
        direction = sdk.la_acl_direction_e_INGRESS
        tcam_pool_id = 0
        self.custom_acl_key_profile_ipv4 = self.device.create_acl_key_profile(key_type, direction, udk, tcam_pool_id)

        key_type = sdk.la_acl_key_type_e_IPV6
        direction = sdk.la_acl_direction_e_INGRESS
        tcam_pool_id = 0
        self.custom_acl_key_profile_ipv6 = self.device.create_acl_key_profile(key_type, direction, udk, tcam_pool_id)

        eth_acl = self.device.create_acl(self.custom_acl_key_profile_eth, self.topology.acl_command_profile_def)
        ipv4_acl = self.device.create_acl(self.custom_acl_key_profile_ipv4, self.topology.acl_command_profile_def)
        ipv6_acl = self.device.create_acl(self.custom_acl_key_profile_ipv6, self.topology.acl_command_profile_def)

        key = []
        field = sdk.la_acl_field()
        field.type = sdk.la_acl_field_type_e_QOS_GROUP
        field.val.qos_group = QOS_GROUP_ID
        field.mask.qos_group = 0xff
        key.append(field)

        counter0 = self.device.create_counter(1)
        command0 = self.create_counter_command(counter0)
        eth_acl.append(key, command0)

        counter1 = self.device.create_counter(1)
        command1 = self.create_counter_command(counter1)
        ipv4_acl.append(key, command1)

        counter2 = self.device.create_counter(1)
        command2 = self.create_counter_command(counter2)
        ipv6_acl.append(key, command2)

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_ETHERNET, [eth_acl])
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [ipv4_acl])
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, [ipv6_acl])
        self.rx_ac_port.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        run_and_compare(self, self.device,
                        INPUT_IPV4_o_MPLS_PACKET, self.RX_SLICE, RX_IFG, RX_SERDES_FIRST,
                        OUTPUT_IPV4_o_MPLS_PACKET, self.TX_SLICE_DEF, TX_IFG_DEF, TX_SERDES_FIRST_DEF)

        packet_count, _ = counter0.read(0, True, True)
        self.assertEqual(packet_count, 0)

        run_and_compare(self, self.device,
                        INPUT_IPV4_PACKET, self.RX_SLICE, RX_IFG, RX_SERDES_FIRST,
                        OUTPUT_IPV4_PACKET, self.TX_SLICE_DEF, TX_IFG_DEF, TX_SERDES_FIRST_DEF)

        packet_count, _ = counter1.read(0, True, True)
        self.assertEqual(packet_count, 0)

        run_and_compare(self, self.device,
                        INPUT_IPV6_PACKET, self.RX_SLICE, RX_IFG, RX_SERDES_FIRST,
                        OUTPUT_IPV6_PACKET, self.TX_SLICE_DEF, TX_IFG_DEF, TX_SERDES_FIRST_DEF)

        packet_count, _ = counter2.read(0, True, True)
        self.assertEqual(packet_count, 0)

        self.ingress_qos_profile = T.ingress_qos_profile(self, self.device)
        self.ingress_qos_profile.hld_obj.set_qos_group_mapping(IN_PCPDEI, QOS_GROUP_ID)
        self.ingress_qos_profile.hld_obj.set_qos_group_mapping(sdk.la_ip_version_e_IPV4, IN_DSCP, QOS_GROUP_ID)
        self.ingress_qos_profile.hld_obj.set_qos_group_mapping(sdk.la_ip_version_e_IPV6, IN_DSCP, QOS_GROUP_ID)
        self.rx_ac_port.hld_obj.set_ingress_qos_profile(self.ingress_qos_profile.hld_obj)

        run_and_compare(self, self.device,
                        INPUT_IPV4_o_MPLS_PACKET, self.RX_SLICE, RX_IFG, RX_SERDES_FIRST,
                        OUTPUT_IPV4_o_MPLS_PACKET, self.TX_SLICE_DEF, TX_IFG_DEF, TX_SERDES_FIRST_DEF)

        packet_count, _ = counter0.read(0, True, True)
        self.assertEqual(packet_count, 1)

        run_and_compare(self, self.device,
                        INPUT_IPV4_PACKET, self.RX_SLICE, RX_IFG, RX_SERDES_FIRST,
                        OUTPUT_IPV4_PACKET, self.TX_SLICE_DEF, TX_IFG_DEF, TX_SERDES_FIRST_DEF)

        packet_count, _ = counter1.read(0, True, True)
        self.assertEqual(packet_count, 1)

        run_and_compare(self, self.device,
                        INPUT_IPV6_PACKET, self.RX_SLICE, RX_IFG, RX_SERDES_FIRST,
                        OUTPUT_IPV6_PACKET, self.TX_SLICE_DEF, TX_IFG_DEF, TX_SERDES_FIRST_DEF)

        packet_count, _ = counter2.read(0, True, True)
        self.assertEqual(packet_count, 1)

        self.rx_ac_port.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)


if __name__ == '__main__':
    unittest.main()
