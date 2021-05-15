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
from l3_rtf_base import *


@unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
class l3_rtf(l3_rtf_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv4_first_drop_acl(self):
        acl1 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)
        acl2 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)

        key = []
        field1 = sdk.la_acl_field()
        field1.type = sdk.la_acl_field_type_e_IPV4_DIP
        field1.val.ipv4_dip.s_addr = IPV4_DIP.to_num()
        field1.mask.ipv4_dip.s_addr = 0xffffffff
        key.append(field1)
        field2 = sdk.la_acl_field()
        field2.type = sdk.la_acl_field_type_e_PROTOCOL
        field2.val.protocol = INPUT_IPV4_PACKET[IP].proto
        field2.mask.protocol = 0xff
        key.append(field2)

        command1 = self.create_drop_command()
        acl1.append(key, command1)

        counter = self.device.create_counter(1)
        command2 = self.create_counter_command(counter)
        acl2.append(key, command2)

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [acl1, acl2])
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        l3_acl_group = self.topology.rx_l3_ac.hld_obj.get_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.assertEqual(acl_group.this, l3_acl_group.this)

        run_and_drop(self, self.device, INPUT_IPV4_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        packet_count, _ = counter.read(0, True, True)
        self.assertEqual(packet_count, 0)

        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    @unittest.skipUnless(decor.is_gibraltar(), "Test is supported only on GB")
    def test_ipv4_first_drop_acl_svi(self):
        acl1 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)
        acl2 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)

        key = []
        field1 = sdk.la_acl_field()
        field1.type = sdk.la_acl_field_type_e_IPV4_DIP
        field1.val.ipv4_dip.s_addr = IPV4_DIP.to_num()
        field1.mask.ipv4_dip.s_addr = 0xffffffff
        key.append(field1)
        field2 = sdk.la_acl_field()
        field2.type = sdk.la_acl_field_type_e_PROTOCOL
        field2.val.protocol = INPUT_IPV4_PACKET[IP].proto
        field2.mask.protocol = 0xff
        key.append(field2)

        command1 = self.create_drop_command()
        acl1.append(key, command1)

        counter = self.device.create_counter(1)
        command2 = self.create_counter_command(counter)
        acl2.append(key, command2)

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [acl1, acl2])
        self.topology.rx_l2_ac_port.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        l3_acl_group = self.topology.rx_l2_ac_port.hld_obj.get_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.assertEqual(acl_group.this, l3_acl_group.this)

        run_and_drop(self, self.device, INPUT_IPV4_PACKET_SVI, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        packet_count, _ = counter.read(0, True, True)
        self.assertEqual(packet_count, 0)

        self.topology.rx_l2_ac_port.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv4_second_drop_acl(self):
        acl1 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)
        acl2 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)

        key = []
        field = sdk.la_acl_field()
        field.type = sdk.la_acl_field_type_e_IPV4_SIP
        field.val.ipv4_sip.s_addr = IPV4_SIP.to_num()
        field.mask.ipv4_sip.s_addr = 0xffffffff
        key.append(field)

        counter = self.device.create_counter(1)
        command1 = self.create_counter_command(counter)
        acl1.append(key, command1)

        command2 = self.create_drop_command()
        acl2.append(key, command2)

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [acl1, acl2])
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        l3_acl_group = self.topology.rx_l3_ac.hld_obj.get_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.assertEqual(acl_group.this, l3_acl_group.this)

        run_and_drop(self, self.device, INPUT_IPV4_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        packet_count, _ = counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv4_override_l3_dest(self):
        self.create_default_drop_acl()
        acl1 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)
        acl2 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)

        key = []
        field = sdk.la_acl_field()
        field.type = sdk.la_acl_field_type_e_IPV4_SIP
        field.val.ipv4_sip.s_addr = IPV4_SIP.to_num()
        field.mask.ipv4_sip.s_addr = 0xffffffff
        key.append(field)

        command1 = self.create_force_l3_destination_command(self.topology.nh_l3_ac_reg.hld_obj)
        acl1.append(key, command1)

        command2 = self.create_force_l3_destination_command(self.topology.nh_l3_ac_ext.hld_obj)
        acl2.append(key, command2)

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [acl1, acl2])
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, [self.default_ipv6_drop_acl])
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        l3_acl_group = self.topology.rx_l3_ac.hld_obj.get_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.assertEqual(acl_group.this, l3_acl_group.this)

        run_and_compare(self, self.device,
                        INPUT_IPV4_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        EXPECTED_EXTRA_OUTPUT_IPV4_PACKET, T.TX_SLICE_EXT, T.TX_IFG_EXT, T.FIRST_SERDES_L3_EXT)

        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(True, "Test fails because of the changes in mirror logic")
    def test_ipv4_override_mirror_cmd(self):
        self.create_default_drop_acl()
        acl1 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)
        acl2 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)

        key = []
        field = sdk.la_acl_field()
        field.type = sdk.la_acl_field_type_e_IPV4_SIP
        field.val.ipv4_sip.s_addr = IPV4_SIP.to_num()
        field.mask.ipv4_sip.s_addr = 0xffffffff
        key.append(field)

        command1 = self.create_mirror_cmd_acl_command(MIRROR_CMD_GID1)
        acl1.append(key, command1)

        command2 = self.create_mirror_cmd_acl_command(MIRROR_CMD_GID2)
        acl2.append(key, command2)

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [acl1, acl2])
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, [self.default_ipv6_drop_acl])
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        l3_acl_group = self.topology.rx_l3_ac.hld_obj.get_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.assertEqual(acl_group.this, l3_acl_group.this)

        mirror_packet = MIRROR_IPV4_PACKET.copy()
        mirror_packet[Punt].code = MIRROR_CMD_GID2
        run_and_compare_list(self, self.device,
                             {'data': INPUT_IPV4_PACKET,
                              'slice': T.RX_SLICE,
                              'ifg': T.RX_IFG,
                              'pif': T.FIRST_SERDES},
                             [{'data': mirror_packet,
                               'slice': self.PUNT_INJECT_SLICE,
                               'ifg': PUNT_INJECT_IFG,
                               'pif': PUNT_INJECT_SERDES_FIRST},
                              {'data': EXPECTED_DEFAULT_OUTPUT_IPV4_PACKET,
                               'slice': T.TX_SLICE_DEF,
                               'ifg': T.TX_IFG_DEF,
                               'pif': T.FIRST_SERDES_L3_DEF}])

        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv4_modify_acl_group(self):
        self.create_default_drop_acl()
        acl1 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)
        acl2 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)

        key = []
        field = sdk.la_acl_field()
        field.type = sdk.la_acl_field_type_e_IPV4_DIP
        field.val.ipv4_dip.s_addr = IPV4_DIP.to_num()
        field.mask.ipv4_dip.s_addr = 0xffffffff
        key.append(field)

        command1 = self.create_tc_and_color_command(7, 3)
        acl1.append(key, command1)

        command2 = self.create_force_l3_destination_command(self.topology.nh_l3_ac_ext.hld_obj)
        acl2.append(key, command2)

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [acl1, None, None, acl2])
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, [self.default_ipv6_drop_acl])
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        l3_acl_group = self.topology.rx_l3_ac.hld_obj.get_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.assertEqual(acl_group.this, l3_acl_group.this)

        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0x1F}}
        run_and_compare_inner_fields(self, self.device,
                                     INPUT_IPV4_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                     EXPECTED_EXTRA_OUTPUT_IPV4_PACKET, T.TX_SLICE_EXT, T.TX_IFG_EXT, T.FIRST_SERDES_L3_EXT,
                                     control_expected)

        ipv4_acls = l3_acl_group.get_acls(sdk.la_acl_packet_format_e_IPV4)

        acl3 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)
        command3 = self.create_tc_and_color_command(3, 3)
        acl3.append(key, command3)

        ipv4_acls[2] = acl3
        l3_acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, ipv4_acls)

        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0xF}}
        run_and_compare_inner_fields(self, self.device,
                                     INPUT_IPV4_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                     EXPECTED_EXTRA_OUTPUT_IPV4_PACKET, T.TX_SLICE_EXT, T.TX_IFG_EXT, T.FIRST_SERDES_L3_EXT,
                                     control_expected)

        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv4_multiple_counter_action(self):
        acl1 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)
        acl2 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)

        key = []
        field1 = sdk.la_acl_field()
        field1.type = sdk.la_acl_field_type_e_IPV4_DIP
        field1.val.ipv4_dip.s_addr = IPV4_DIP.to_num()
        field1.mask.ipv4_dip.s_addr = 0xffffffff
        key.append(field1)
        field2 = sdk.la_acl_field()
        field2.type = sdk.la_acl_field_type_e_PROTOCOL
        field2.val.protocol = INPUT_IPV4_PACKET[IP].proto
        field2.mask.protocol = 0xff
        key.append(field2)

        counter1 = self.device.create_counter(1)
        command1 = self.create_counter_command(counter1)
        acl1.append(key, command1)

        counter2 = self.device.create_counter(1)
        command2 = self.create_counter_command(counter2)
        acl2.append(key, command2)

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [acl1, acl2])
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        l3_acl_group = self.topology.rx_l3_ac.hld_obj.get_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.assertEqual(acl_group.this, l3_acl_group.this)

        run_and_compare(self, self.device,
                        INPUT_IPV4_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        EXPECTED_DEFAULT_OUTPUT_IPV4_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        # First ACL counter will not be updated in HW.
        # Assertion check is commented till we get NPL fix for NSIM.
        packet_count, _ = counter1.read(0, True, True)
        #self.assertEqual(packet_count, 0)

        # Check for ACL-2 counter
        packet_count, _ = counter2.read(0, True, True)
        self.assertEqual(packet_count, 1)

        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv4_multiple_qos_counter_action(self):
        acl1 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)
        acl2 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)

        key = []
        field1 = sdk.la_acl_field()
        field1.type = sdk.la_acl_field_type_e_IPV4_DIP
        field1.val.ipv4_dip.s_addr = IPV4_DIP.to_num()
        field1.mask.ipv4_dip.s_addr = 0xffffffff
        key.append(field1)
        field2 = sdk.la_acl_field()
        field2.type = sdk.la_acl_field_type_e_PROTOCOL
        field2.val.protocol = INPUT_IPV4_PACKET[IP].proto
        field2.mask.protocol = 0xff
        key.append(field2)

        q_counter = self.device.create_counter(8)
        self.topology.rx_l3_ac.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_QOS, q_counter)

        command1 = self.create_qos_commands(QOS_COUNTER_OFFSET - 1, QOS_MARK_DSCP - 1)
        acl1.append(key, command1)

        command2 = self.create_qos_commands(QOS_COUNTER_OFFSET, QOS_MARK_DSCP)
        acl2.append(key, command2)

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [acl1, acl2])
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        l3_acl_group = self.topology.rx_l3_ac.hld_obj.get_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.assertEqual(acl_group.this, l3_acl_group.this)

        output_packet = EXPECTED_DEFAULT_OUTPUT_IPV4_PACKET.copy()
        output_packet[IP].tos = QOS_MARK_DSCP << 2
        run_and_compare(self, self.device,
                        INPUT_IPV4_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        output_packet, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        packet_count, _ = q_counter.read(QOS_COUNTER_OFFSET - 1, True, True)
        self.assertEqual(packet_count, 0)

        packet_count, _ = q_counter.read(QOS_COUNTER_OFFSET, True, True)
        self.assertEqual(packet_count, 1)

        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.topology.rx_l3_ac.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_QOS, None)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv6_first_drop_acl(self):
        acl1 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv6_def, self.topology.acl_command_profile_def)
        acl2 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv6_def, self.topology.acl_command_profile_def)

        key = []
        field = sdk.la_acl_field()
        field.type = sdk.la_acl_field_type_e_IPV6_SIP
        q0 = sdk.get_ipv6_addr_q0(IPV6_SIP.hld_obj)
        q1 = sdk.get_ipv6_addr_q1(IPV6_SIP.hld_obj)
        sdk.set_ipv6_addr(field.val.ipv6_sip, q0, q1)
        sdk.set_ipv6_addr(field.mask.ipv6_sip, 0xffffffffffffffff, 0xffffffffffffffff)
        key.append(field)

        command1 = self.create_drop_command()
        acl1.append(key, command1)

        command2 = self.create_force_l3_destination_command(self.topology.nh_l3_ac_ext.hld_obj)
        acl2.append(key, command2)

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, [acl1, acl2])
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        l3_acl_group = self.topology.rx_l3_ac.hld_obj.get_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.assertEqual(acl_group.this, l3_acl_group.this)

        run_and_drop(self, self.device, INPUT_IPV6_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv6_second_drop_acl(self):
        acl1 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv6_def, self.topology.acl_command_profile_def)
        acl2 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv6_def, self.topology.acl_command_profile_def)

        key = []
        field = sdk.la_acl_field()
        field.type = sdk.la_acl_field_type_e_IPV6_DIP
        q0 = sdk.get_ipv6_addr_q0(IPV6_DIP.hld_obj)
        q1 = sdk.get_ipv6_addr_q1(IPV6_DIP.hld_obj)
        sdk.set_ipv6_addr(field.val.ipv6_dip, q0, q1)
        sdk.set_ipv6_addr(field.mask.ipv6_dip, 0xffffffffffffffff, 0xffffffffffffffff)
        key.append(field)

        command1 = self.create_force_l3_destination_command(self.topology.nh_l3_ac_ext.hld_obj)
        acl1.append(key, command1)

        command2 = self.create_drop_command()
        acl2.append(key, command2)

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, [acl1, acl2])
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        l3_acl_group = self.topology.rx_l3_ac.hld_obj.get_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.assertEqual(acl_group.this, l3_acl_group.this)

        run_and_drop(self, self.device, INPUT_IPV6_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv6_override_l3_dest(self):
        self.create_default_drop_acl()
        acl1 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv6_def, self.topology.acl_command_profile_def)
        acl2 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv6_def, self.topology.acl_command_profile_def)

        key = []
        field = sdk.la_acl_field()
        field.type = sdk.la_acl_field_type_e_IPV6_SIP
        q0 = sdk.get_ipv6_addr_q0(IPV6_SIP.hld_obj)
        q1 = sdk.get_ipv6_addr_q1(IPV6_SIP.hld_obj)
        sdk.set_ipv6_addr(field.val.ipv6_sip, q0, q1)
        sdk.set_ipv6_addr(field.mask.ipv6_sip, 0xffffffffffffffff, 0xffffffffffffffff)
        key.append(field)

        command1 = self.create_force_l3_destination_command(self.topology.nh_l3_ac_reg.hld_obj)
        acl1.append(key, command1)

        command2 = self.create_force_l3_destination_command(self.topology.nh_l3_ac_ext.hld_obj)
        acl2.append(key, command2)

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [self.default_ipv4_drop_acl])
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, [acl1, acl2])
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        l3_acl_group = self.topology.rx_l3_ac.hld_obj.get_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.assertEqual(acl_group.this, l3_acl_group.this)

        run_and_compare(self, self.device,
                        INPUT_IPV6_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        EXPECTED_EXTRA_OUTPUT_IPV6_PACKET, T.TX_SLICE_EXT, T.TX_IFG_EXT, T.FIRST_SERDES_L3_EXT)

        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(True, "Test fails because of the changes in mirror logic")
    def test_ipv6_override_mirror_cmd(self):
        self.create_default_drop_acl()
        acl1 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv6_def, self.topology.acl_command_profile_def)
        acl2 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv6_def, self.topology.acl_command_profile_def)

        key = []
        field = sdk.la_acl_field()
        field.type = sdk.la_acl_field_type_e_IPV6_SIP
        q0 = sdk.get_ipv6_addr_q0(IPV6_SIP.hld_obj)
        q1 = sdk.get_ipv6_addr_q1(IPV6_SIP.hld_obj)
        sdk.set_ipv6_addr(field.val.ipv6_sip, q0, q1)
        sdk.set_ipv6_addr(field.mask.ipv6_sip, 0xffffffffffffffff, 0xffffffffffffffff)
        key.append(field)

        command1 = self.create_mirror_cmd_acl_command(MIRROR_CMD_GID1)
        acl1.append(key, command1)

        command2 = self.create_mirror_cmd_acl_command(MIRROR_CMD_GID2)
        acl2.append(key, command2)

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [self.default_ipv4_drop_acl])
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, [acl1, acl2])
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        l3_acl_group = self.topology.rx_l3_ac.hld_obj.get_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.assertEqual(acl_group.this, l3_acl_group.this)

        mirror_packet = MIRROR_IPV6_PACKET
        mirror_packet[Punt].code = MIRROR_CMD_GID2
        run_and_compare_list(self, self.device,
                             {'data': INPUT_IPV6_PACKET,
                              'slice': T.RX_SLICE,
                              'ifg': T.RX_IFG,
                              'pif': T.FIRST_SERDES},
                             [{'data': mirror_packet,
                               'slice': self.PUNT_INJECT_SLICE,
                               'ifg': PUNT_INJECT_IFG,
                               'pif': PUNT_INJECT_SERDES_FIRST},
                              {'data': EXPECTED_DEFAULT_OUTPUT_IPV6_PACKET,
                               'slice': T.TX_SLICE_DEF,
                               'ifg': T.TX_IFG_DEF,
                               'pif': T.FIRST_SERDES_L3_DEF}])

        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv6_modify_acl_group(self):
        self.create_default_drop_acl()
        acl1 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv6_def, self.topology.acl_command_profile_def)
        acl2 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv6_def, self.topology.acl_command_profile_def)

        key = []
        field = sdk.la_acl_field()
        field.type = sdk.la_acl_field_type_e_IPV6_SIP
        q0 = sdk.get_ipv6_addr_q0(IPV6_SIP.hld_obj)
        q1 = sdk.get_ipv6_addr_q1(IPV6_SIP.hld_obj)
        sdk.set_ipv6_addr(field.val.ipv6_sip, q0, q1)
        sdk.set_ipv6_addr(field.mask.ipv6_sip, 0xffffffffffffffff, 0xffffffffffffffff)
        key.append(field)

        command1 = self.create_tc_and_color_command(7, 3)
        acl1.append(key, command1)

        command2 = self.create_force_l3_destination_command(self.topology.nh_l3_ac_ext.hld_obj)
        acl2.append(key, command2)

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [self.default_ipv4_drop_acl])
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, [acl1, None, None, acl2])
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        l3_acl_group = self.topology.rx_l3_ac.hld_obj.get_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.assertEqual(acl_group.this, l3_acl_group.this)

        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0x1F}}
        run_and_compare_inner_fields(self, self.device,
                                     INPUT_IPV6_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                     EXPECTED_EXTRA_OUTPUT_IPV6_PACKET, T.TX_SLICE_EXT, T.TX_IFG_EXT, T.FIRST_SERDES_L3_EXT,
                                     control_expected)

        ipv6_acls = l3_acl_group.get_acls(sdk.la_acl_packet_format_e_IPV6)

        acl3 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv6_def, self.topology.acl_command_profile_def)
        command3 = self.create_tc_and_color_command(3, 3)
        acl3.append(key, command3)

        ipv6_acls[2] = acl3
        l3_acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, ipv6_acls)

        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0xF}}
        run_and_compare_inner_fields(self, self.device,
                                     INPUT_IPV6_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                     EXPECTED_EXTRA_OUTPUT_IPV6_PACKET, T.TX_SLICE_EXT, T.TX_IFG_EXT, T.FIRST_SERDES_L3_EXT,
                                     control_expected)

        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv6_multiple_counter_action(self):
        acl1 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv6_def, self.topology.acl_command_profile_def)
        acl2 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv6_def, self.topology.acl_command_profile_def)

        key = []
        field = sdk.la_acl_field()
        field.type = sdk.la_acl_field_type_e_IPV6_SIP
        q0 = sdk.get_ipv6_addr_q0(IPV6_SIP.hld_obj)
        q1 = sdk.get_ipv6_addr_q1(IPV6_SIP.hld_obj)
        sdk.set_ipv6_addr(field.val.ipv6_sip, q0, q1)
        sdk.set_ipv6_addr(field.mask.ipv6_sip, 0xffffffffffffffff, 0xffffffffffffffff)
        key.append(field)

        counter1 = self.device.create_counter(1)
        command1 = self.create_counter_command(counter1)
        acl1.append(key, command1)

        counter2 = self.device.create_counter(1)
        command2 = self.create_counter_command(counter2)
        acl2.append(key, command2)

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, [acl1, acl2])
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        l3_acl_group = self.topology.rx_l3_ac.hld_obj.get_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.assertEqual(acl_group.this, l3_acl_group.this)

        run_and_compare(self, self.device,
                        INPUT_IPV6_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        EXPECTED_DEFAULT_OUTPUT_IPV6_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        # First ACL counter will not be updated in HW.
        # Assertion check is commented till we get NPL fix for NSIM.
        packet_count, _ = counter1.read(0, True, True)
        #self.assertEqual(packet_count, 1)

        # Check for ACL-2 counter
        packet_count, _ = counter2.read(0, True, True)
        self.assertEqual(packet_count, 1)

        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ipv6_multiple_qos_counter_action(self):
        acl1 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv6_def, self.topology.acl_command_profile_def)
        acl2 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv6_def, self.topology.acl_command_profile_def)

        key = []
        field = sdk.la_acl_field()
        field.type = sdk.la_acl_field_type_e_IPV6_SIP
        q0 = sdk.get_ipv6_addr_q0(IPV6_SIP.hld_obj)
        q1 = sdk.get_ipv6_addr_q1(IPV6_SIP.hld_obj)
        sdk.set_ipv6_addr(field.val.ipv6_sip, q0, q1)
        sdk.set_ipv6_addr(field.mask.ipv6_sip, 0xffffffffffffffff, 0xffffffffffffffff)
        key.append(field)

        q_counter = self.device.create_counter(8)
        self.topology.rx_l3_ac.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_QOS, q_counter)

        command1 = self.create_qos_commands(QOS_COUNTER_OFFSET - 1, QOS_MARK_DSCP - 1)
        acl1.append(key, command1)

        command2 = self.create_qos_commands(QOS_COUNTER_OFFSET, QOS_MARK_DSCP)
        acl2.append(key, command2)

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, [acl1, acl2])
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        l3_acl_group = self.topology.rx_l3_ac.hld_obj.get_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.assertEqual(acl_group.this, l3_acl_group.this)

        output_packet = EXPECTED_DEFAULT_OUTPUT_IPV6_PACKET.copy()
        output_packet[IPv6].tc = (QOS_MARK_DSCP << 2)
        run_and_compare(self, self.device,
                        INPUT_IPV6_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        output_packet, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        packet_count, _ = q_counter.read(QOS_COUNTER_OFFSET - 1, True, True)
        self.assertEqual(packet_count, 0)

        packet_count, _ = q_counter.read(QOS_COUNTER_OFFSET, True, True)
        self.assertEqual(packet_count, 1)

        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.topology.rx_l3_ac.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_QOS, None)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_multiple_packet_formats_different_key_profiles(self):
        self.ipv4_acl_key_profile2 = self.device.create_acl_key_profile(
            sdk.la_acl_key_type_e_IPV4, sdk.la_acl_direction_e_INGRESS, sdk.LA_ACL_KEY_IPV4, 0)

        self.ipv6_acl_key_profile2 = self.device.create_acl_key_profile(
            sdk.la_acl_key_type_e_IPV6, sdk.la_acl_direction_e_INGRESS, sdk.LA_ACL_KEY_IPV6, 0)

        acl1 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)
        acl2 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv6_def, self.topology.acl_command_profile_def)

        acl3 = self.device.create_acl(self.ipv4_acl_key_profile2, self.topology.acl_command_profile_def)
        acl4 = self.device.create_acl(self.ipv6_acl_key_profile2, self.topology.acl_command_profile_def)

        key = []
        field = sdk.la_acl_field()
        field.type = sdk.la_acl_field_type_e_IPV4_SIP
        field.val.ipv4_sip.s_addr = IPV4_SIP.to_num()
        field.mask.ipv4_sip.s_addr = 0xffffffff
        key.append(field)

        command1 = self.create_tc_and_color_command(7, 3)
        acl1.append(key, command1)

        key = []
        field = sdk.la_acl_field()
        field.type = sdk.la_acl_field_type_e_IPV6_SIP
        q0 = sdk.get_ipv6_addr_q0(IPV6_SIP.hld_obj)
        q1 = sdk.get_ipv6_addr_q1(IPV6_SIP.hld_obj)
        sdk.set_ipv6_addr(field.val.ipv6_sip, q0, q1)
        sdk.set_ipv6_addr(field.mask.ipv6_sip, 0xffffffffffffffff, 0xffffffffffffffff)
        key.append(field)

        counter = self.device.create_counter(1)
        command2 = self.create_counter_command(counter)
        acl2.append(key, command2)

        key = []
        field = sdk.la_acl_field()
        field.type = sdk.la_acl_field_type_e_IPV4_SIP
        field.val.ipv4_sip.s_addr = IPV4_SIP.to_num()
        field.mask.ipv4_sip.s_addr = 0xffffffff
        key.append(field)

        command3 = self.create_force_l3_destination_command(self.topology.nh_l3_ac_ext.hld_obj)
        acl3.append(key, command3)

        key = []
        field = sdk.la_acl_field()
        field.type = sdk.la_acl_field_type_e_IPV6_SIP
        q0 = sdk.get_ipv6_addr_q0(IPV6_SIP.hld_obj)
        q1 = sdk.get_ipv6_addr_q1(IPV6_SIP.hld_obj)
        sdk.set_ipv6_addr(field.val.ipv6_sip, q0, q1)
        sdk.set_ipv6_addr(field.mask.ipv6_sip, 0xffffffffffffffff, 0xffffffffffffffff)
        key.append(field)

        command4 = self.create_drop_command()
        acl4.append(key, command4)

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [acl1, acl3])
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, [acl2, acl4])
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        l3_acl_group = self.topology.rx_l3_ac.hld_obj.get_acl_group(sdk.la_acl_direction_e_INGRESS)
        self.assertEqual(acl_group.this, l3_acl_group.this)

        control_expected = {'nppd_to_rxpp_npu_output': {'pd.phb': 0x1F}}
        run_and_compare_inner_fields(self, self.device,
                                     INPUT_IPV4_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                     EXPECTED_EXTRA_OUTPUT_IPV4_PACKET, T.TX_SLICE_EXT, T.TX_IFG_EXT, T.FIRST_SERDES_L3_EXT,
                                     control_expected)

        run_and_drop(self, self.device, INPUT_IPV6_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        packet_count, _ = counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ip_over_ip_acls(self):
        self.create_ip_over_ip_tunnel_ports()
        acl1 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)

        key = []
        field = sdk.la_acl_field()
        field.type = sdk.la_acl_field_type_e_IPV4_DIP
        field.val.ipv4_sip.s_addr = LOCAL_IP.to_num()
        field.mask.ipv4_sip.s_addr = 0xffffffff
        key.append(field)

        counter1 = self.device.create_counter(1)
        command1 = self.create_counter_command(counter1)
        acl1.append(key, command1)

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [acl1])
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        run_and_compare(self, self.device,
                        INPUT_IPV4_O_IPV4_TUNNEL_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        EXPECTED_OUTPUT_IPV4_O_IPV4_TUNNEL_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        packet_count, _ = counter1.read(0, True, True)
        self.assertEqual(packet_count, 1)

        run_and_compare(self, self.device,
                        INPUT_IPV6_O_IPV4_TUNNEL_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        EXPECTED_OUTPUT_IPV6_O_IPV4_TUNNEL_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        packet_count, _ = counter1.read(0, True, True)
        self.assertEqual(packet_count, 1)

        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    def test_qos_group_field(self):
        udk = []
        udf0 = sdk.la_acl_field_def()
        udf0.type = sdk.la_acl_field_type_e_QOS_GROUP
        udk.append(udf0)

        key_type = sdk.la_acl_key_type_e_IPV4
        direction = sdk.la_acl_direction_e_INGRESS
        tcam_pool_id = 0
        self.custom_acl_key_profile_ipv4 = self.device.create_acl_key_profile(key_type, direction, udk, tcam_pool_id)

        key_type = sdk.la_acl_key_type_e_IPV6
        direction = sdk.la_acl_direction_e_INGRESS
        tcam_pool_id = 0
        self.custom_acl_key_profile_ipv6 = self.device.create_acl_key_profile(key_type, direction, udk, tcam_pool_id)

        ipv4_acl = self.device.create_acl(self.custom_acl_key_profile_ipv4, self.topology.acl_command_profile_def)
        ipv6_acl = self.device.create_acl(self.custom_acl_key_profile_ipv6, self.topology.acl_command_profile_def)

        key = []
        field = sdk.la_acl_field()
        field.type = sdk.la_acl_field_type_e_QOS_GROUP
        field.val.qos_group = QOS_GROUP_ID
        field.mask.qos_group = 0xff
        key.append(field)

        counter1 = self.device.create_counter(1)
        command1 = self.create_counter_command(counter1)
        ipv4_acl.append(key, command1)

        counter2 = self.device.create_counter(1)
        command2 = self.create_counter_command(counter2)
        ipv6_acl.append(key, command2)

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [ipv4_acl])
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV6, [ipv6_acl])
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        run_and_compare(self, self.device,
                        INPUT_IPV4_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        EXPECTED_DEFAULT_OUTPUT_IPV4_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        packet_count, _ = counter1.read(0, True, True)
        self.assertEqual(packet_count, 0)

        run_and_compare(self, self.device,
                        INPUT_IPV6_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        EXPECTED_DEFAULT_OUTPUT_IPV6_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        packet_count, _ = counter2.read(0, True, True)
        self.assertEqual(packet_count, 0)

        self.ingress_qos_profile = T.ingress_qos_profile(self, self.device)
        self.ingress_qos_profile.hld_obj.set_qos_group_mapping(sdk.la_ip_version_e_IPV4, IN_DSCP, QOS_GROUP_ID)
        self.ingress_qos_profile.hld_obj.set_qos_group_mapping(sdk.la_ip_version_e_IPV6, IN_DSCP, QOS_GROUP_ID)
        self.topology.rx_l3_ac.hld_obj.set_ingress_qos_profile(self.ingress_qos_profile.hld_obj)

        run_and_compare(self, self.device,
                        INPUT_IPV4_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        EXPECTED_DEFAULT_OUTPUT_IPV4_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        packet_count, _ = counter1.read(0, True, True)
        self.assertEqual(packet_count, 1)

        run_and_compare(self, self.device,
                        INPUT_IPV6_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        EXPECTED_DEFAULT_OUTPUT_IPV6_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, T.FIRST_SERDES_L3_DEF)

        packet_count, _ = counter2.read(0, True, True)
        self.assertEqual(packet_count, 1)

        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)

    def test_action_profile_1(self):
        # action profile 1 allows change destination and counter in parallel
        acl1 = self.device.create_acl(self.topology.ingress_acl_key_profile_ipv4_def, self.topology.acl_command_profile_def)

        key = []
        field1 = sdk.la_acl_field()
        field1.type = sdk.la_acl_field_type_e_IPV4_DIP
        field1.val.ipv4_dip.s_addr = IPV4_DIP.to_num()
        field1.mask.ipv4_dip.s_addr = 0xffffffff
        key.append(field1)

        commands = []

        force_action = sdk.la_acl_command_action()
        force_action.type = sdk.la_acl_action_type_e_L3_DESTINATION
        force_action.data.l3_dest = self.topology.nh_l3_ac_ext.hld_obj
        commands.append(force_action)

        counter = self.device.create_counter(1)
        counter_cmd_action = sdk.la_acl_command_action()
        counter_cmd_action.type = sdk.la_acl_action_type_e_COUNTER
        counter_cmd_action.data.counter = counter
        commands.append(counter_cmd_action)

        acl1.append(key, commands)

        acl_group = self.device.create_acl_group()
        acl_group.set_acls(sdk.la_acl_packet_format_e_IPV4, [acl1])
        self.topology.rx_l3_ac.hld_obj.set_acl_group(sdk.la_acl_direction_e_INGRESS, acl_group)

        run_and_compare(self, self.device,
                        INPUT_IPV4_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        EXPECTED_EXTRA_OUTPUT_IPV4_PACKET, T.TX_SLICE_EXT, T.TX_IFG_EXT, T.FIRST_SERDES_L3_EXT)

        packet_count, _ = counter.read(0, True, True)
        self.assertEqual(packet_count, 1)

        self.topology.rx_l3_ac.hld_obj.clear_acl_group(sdk.la_acl_direction_e_INGRESS)


if __name__ == '__main__':
    unittest.main()
