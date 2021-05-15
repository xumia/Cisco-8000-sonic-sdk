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

import os
import sys
import unittest
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import decor
import topology as T
import warm_boot_test_utils as wb
import sdk_test_case_base

PRIVATE_DATA = 0x1234567890abcdef

TTL = 128
SA = T.mac_addr('be:ef:5d:35:7a:35')
DA = T.mac_addr('02:02:02:02:02:02')

PUNT_INJECT_PORT_MAC_ADDR = T.mac_addr("12:34:56:78:9a:bc")
HOST_MAC_ADDR = T.mac_addr("fe:dc:ba:98:76:54")
CDP_DA = T.mac_addr('01:00:0C:CC:CC:CC')
PVSTP_DA = T.mac_addr('01:00:0C:CC:CC:CD')
PUNT_VLAN = 0xA13

SYS_PORT_GID_BASE = 23
PI_SP_GID = SYS_PORT_GID_BASE + 2

PI_SLICE = T.get_device_slice(3)
PI_IFG = T.get_device_ifg(1)
PI_PIF_FIRST = T.get_device_first_serdes(8)
PUNT_RELAY_ID = 0 if decor.is_pacific() else T.VRF_GID

S.load_contrib("cdp")

wb.support_warm_boot()


@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
@unittest.skipIf(decor.is_auto_warm_boot_enabled(), "Skip in auto-WB sanity")
@unittest.skipUnless(decor.is_pacific() or decor.is_gibraltar(), "WB is currently supported by GB and PAC only")
class warm_boot_cdp_meters(sdk_test_case_base.sdk_test_case_base):

    CDP_PACKET_BASE = \
        S.Ether(dst = CDP_DA.addr_str, src = SA.addr_str, type = U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan = T.RX_L3_AC_PORT_VID1, type = U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan = T.RX_L3_AC_PORT_VID2) / \
        S.LLC() / S.SNAP() / CDPv2_HDR()

    CDP_PACKET, __ = U.enlarge_packet_to_min_length(CDP_PACKET_BASE)

    PUNT_PACKET_CDP = \
        S.Ether(dst = HOST_MAC_ADDR.addr_str, src = PUNT_INJECT_PORT_MAC_ADDR.addr_str, type = U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(prio = 0, id = 0, vlan = PUNT_VLAN, type = U.Ethertype.Punt.value) / \
        U.Punt(next_header = sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
               fwd_header_type = sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
               next_header_offset = 0,
               source = sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
               code = sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS,
               source_sp = T.RX_SYS_PORT_GID,
               destination_sp = sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
               source_lp = T.RX_L3_AC_GID,
               # destination_lp=0x7fff,
               destination_lp = sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS,
               relay_id = PUNT_RELAY_ID, lpts_flow_type = 0) / \
        CDP_PACKET

    PVSTP_PACKET_BASE = \
        S.Ether(dst = PVSTP_DA.addr_str, src = SA.addr_str, type = U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan = T.RX_L3_AC_PORT_VID1) / \
        S.LLC() / S.SNAP() / CDPv2_HDR()

    PVSTP_PACKET, __ = U.enlarge_packet_to_min_length(PVSTP_PACKET_BASE)

    PUNT_PACKET_PVSTP = \
        S.Ether(dst = HOST_MAC_ADDR.addr_str, src = PUNT_INJECT_PORT_MAC_ADDR.addr_str, type = U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(prio = 0, id = 0, vlan = PUNT_VLAN, type = U.Ethertype.Punt.value) / \
        U.Punt(next_header = sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
               fwd_header_type = sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
               next_header_offset = 0,
               source = sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
               code = sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS,
               source_sp = T.RX_SYS_PORT_GID,
               destination_sp = sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
               source_lp = 0,
               # destination_lp=0x3ffff,
               destination_lp = sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS,
               relay_id = 0, lpts_flow_type = 0) / \
        PVSTP_PACKET

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        global PI_SLICE
        PI_SLICE = T.choose_active_slices(cls.device, PI_SLICE, [3, 1])

    def setUp(self):
        super().setUp()

        self.pi_port = T.punt_inject_port(
            self,
            self.device,
            PI_SLICE,
            PI_IFG,
            PI_SP_GID,
            PI_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR.addr_str)
        wb.warm_boot(self.device.device)
        self.punt_dest = T.create_l2_punt_destination(
            self,
            self.device,
            T.L2_PUNT_DESTINATION2_GID,
            self.pi_port,
            HOST_MAC_ADDR.addr_str,
            PUNT_VLAN)

        self.warm_boot_file_name = wb.get_warm_boot_file_name()
        self.copc_mac = self.device.create_copc(sdk.la_control_plane_classifier.type_e_MAC)
        self.install_l2cp_entry_in_copc_mac_table(CDP_DA, T.mac_addr('ff:ff:ff:ff:ff:fe'), sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS)

    def tearDown(self):
        self.clear_entries_from_copc_mac_table()
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS)
        super().tearDown()
        if os.path.exists(self.warm_boot_file_name):
            os.remove(self.warm_boot_file_name)

    def install_l2cp_entry_in_copc_mac_table(
            self,
            mac_da_val,
            mac_da_mask,
            result):
        key1 = []
        f1 = sdk.field()
        f1.type.mac = sdk.la_control_plane_classifier.mac_field_type_e_DA
        f1.val.mac.da = mac_da_val.hld_obj
        f1.mask.mac.da = mac_da_mask.hld_obj
        key1.append(f1)

        result1 = sdk.result()
        result1.event = result

        self.copc_mac.append(key1, result1)

    def clear_entries_from_copc_mac_table(self):
        self.copc_mac.clear()

    def test_warm_boot_cdp_meters(self):
        # Create a meter for rate limiting for CDP punt
        cdp_meter = T.create_meter_set(self, self.device, is_aggregate=True)
        wb.warm_boot(self.device.device)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS, 0,
                                           cdp_meter, self.punt_dest, False, False, True, 0)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_NO_SERVICE_MAPPING)

        wb.warm_boot(self.device.device)
        packet_count, byte_count = cdp_meter.read(0, True, True, sdk.la_qos_color_e_GREEN)
        self.assertEqual(packet_count, 0)
        self.assertEqual(byte_count, 0)

        U.run_and_compare(self, self.device,
                          self.CDP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.PUNT_PACKET_CDP, PI_SLICE, PI_IFG, PI_PIF_FIRST)

        wb.warm_boot(self.device.device)
        packet_count, byte_count = cdp_meter.read(0, True, True, sdk.la_qos_color_e_GREEN)
        self.assertEqual(packet_count, 1)

        U.run_and_compare(self, self.device,
                          self.PVSTP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.PUNT_PACKET_PVSTP, PI_SLICE, PI_IFG, PI_PIF_FIRST)

        wb.warm_boot(self.device.device)
        packet_count, byte_count = cdp_meter.read(0, True, True, sdk.la_qos_color_e_GREEN)
        self.assertEqual(packet_count, 1)

    def test_warm_boot_cdp_meters_sdk_down_kernel_module_up(self):
        cdp_meter = T.create_meter_set(self, self.device, is_aggregate=True)
        wb.warm_boot(self.device.device)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS, 0,
                                           cdp_meter, self.punt_dest, False, False, True, 0)
        self.device.clear_trap_configuration(sdk.LA_EVENT_ETHERNET_NO_SERVICE_MAPPING)

        wb.warm_boot(self.device.device)
        packet_count, byte_count = cdp_meter.read(0, True, True, sdk.la_qos_color_e_GREEN)
        self.assertEqual(packet_count, 0)
        self.assertEqual(byte_count, 0)

        py_objs_metadata = wb.warm_boot_disconnect(self.device.device, self.warm_boot_file_name)

        U.run_and_compare(self, self.device,
                          self.CDP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.PUNT_PACKET_CDP, PI_SLICE, PI_IFG, PI_PIF_FIRST)

        wb.warm_boot_reconnect(py_objs_metadata, self.warm_boot_file_name)

        packet_count, byte_count = cdp_meter.read(0, True, True, sdk.la_qos_color_e_GREEN)
        self.assertEqual(packet_count, 1)

        py_objs_metadata = wb.warm_boot_disconnect(self.device.device, self.warm_boot_file_name)

        U.run_and_compare(self, self.device,
                          self.PVSTP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.PUNT_PACKET_PVSTP, PI_SLICE, PI_IFG, PI_PIF_FIRST)

        wb.warm_boot_reconnect(py_objs_metadata, self.warm_boot_file_name)

        packet_count, byte_count = cdp_meter.read(0, True, True, sdk.la_qos_color_e_GREEN)
        self.assertEqual(packet_count, 1)

    def test_warm_boot_cdp_ifg_meters(self):
        cdp_ifg_meter = T.create_meter_set(self, self.device, is_aggregate=True)
        wb.warm_boot(self.device.device)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS, 0,
                                           cdp_ifg_meter, self.punt_dest, False, False, True, 0)

        wb.warm_boot(self.device.device)
        packet_count, byte_count = cdp_ifg_meter.read(0, True, True, sdk.la_qos_color_e_GREEN)
        self.assertEqual(packet_count, 0)
        self.assertEqual(byte_count, 0)

        U.run_and_compare(self, self.device,
                          self.CDP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.PUNT_PACKET_CDP, PI_SLICE, PI_IFG, PI_PIF_FIRST)

        wb.warm_boot(self.device.device)
        packet_count, byte_count = cdp_ifg_meter.read(0, True, True, sdk.la_qos_color_e_GREEN)
        self.assertEqual(packet_count, 1)

    def test_warm_boot_cdp_ifg_meters_sdk_down_kernel_module_up(self):
        cdp_ifg_meter = T.create_meter_set(self, self.device, is_aggregate=True)
        wb.warm_boot(self.device.device)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS, 0,
                                           cdp_ifg_meter, self.punt_dest, False, False, True, 0)

        wb.warm_boot(self.device.device)
        packet_count, byte_count = cdp_ifg_meter.read(0, True, True, sdk.la_qos_color_e_GREEN)
        self.assertEqual(packet_count, 0)
        self.assertEqual(byte_count, 0)

        py_objs_metadata = wb.warm_boot_disconnect(self.device.device, self.warm_boot_file_name)

        U.run_and_compare(self, self.device,
                          self.CDP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.PUNT_PACKET_CDP, PI_SLICE, PI_IFG, PI_PIF_FIRST)

        wb.warm_boot_reconnect(py_objs_metadata, self.warm_boot_file_name)

        packet_count, byte_count = cdp_ifg_meter.read(0, True, True, sdk.la_qos_color_e_GREEN)
        self.assertEqual(packet_count, 1)

    def test_warm_boot_cdp_statistical_meters(self):
        cdp_statistical_meter = T.create_meter_set(self, self.device, is_statistical=True)
        wb.warm_boot(self.device.device)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS, 0,
                                           cdp_statistical_meter, self.punt_dest, False, False, True, 0)

        wb.warm_boot(self.device.device)
        packet_count, byte_count = cdp_statistical_meter.read(0, True, True, sdk.la_qos_color_e_GREEN)
        self.assertEqual(packet_count, 0)
        self.assertEqual(byte_count, 0)

        U.run_and_compare(self, self.device,
                          self.CDP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.PUNT_PACKET_CDP, PI_SLICE, PI_IFG, PI_PIF_FIRST)

        wb.warm_boot(self.device.device)
        packet_count, byte_count = cdp_statistical_meter.read(0, True, True, sdk.la_qos_color_e_GREEN)
        self.assertEqual(packet_count, 1)

    def test_warm_boot_cdp_statistical_meters_sdk_down_kernel_module_up(self):
        cdp_statistical_meter = T.create_meter_set(self, self.device, is_statistical=True)
        wb.warm_boot(self.device.device)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_CISCO_PROTOCOLS, 0,
                                           cdp_statistical_meter, self.punt_dest, False, False, True, 0)

        wb.warm_boot(self.device.device)
        packet_count, byte_count = cdp_statistical_meter.read(0, True, True, sdk.la_qos_color_e_GREEN)
        self.assertEqual(packet_count, 0)
        self.assertEqual(byte_count, 0)

        py_objs_metadata = wb.warm_boot_disconnect(self.device.device, self.warm_boot_file_name)

        U.run_and_compare(self, self.device,
                          self.CDP_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.PUNT_PACKET_CDP, PI_SLICE, PI_IFG, PI_PIF_FIRST)

        wb.warm_boot_reconnect(py_objs_metadata, self.warm_boot_file_name)

        packet_count, byte_count = cdp_statistical_meter.read(0, True, True, sdk.la_qos_color_e_GREEN)
        self.assertEqual(packet_count, 1)


if __name__ == '__main__':
    unittest.main()
