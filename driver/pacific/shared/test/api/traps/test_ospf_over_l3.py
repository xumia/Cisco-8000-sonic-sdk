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

import decor
import sys
import unittest
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import decor
import topology as T
import nplapicli as nplapi
import smart_slices_choise as ssch

from sdk_test_case_base import *

PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"
HOST_MAC_ADDR = "fe:dc:ba:98:76:54"
PUNT_VLAN = 0xA13

SYS_PORT_GID_BASE = 23
IN_SP_GID = SYS_PORT_GID_BASE
OUT_SP_GID = SYS_PORT_GID_BASE + 1

LPTS_FLOW_TYPE_V4 = 10
LPTS_PUNT_CODE_V4 = 120
LPTS_FLOW_TYPE_V6 = 12
LPTS_PUNT_CODE_V6 = 122


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class TrapsOSPFOverL3(sdk_test_case_base):
    PI_SP_GID = SYS_PORT_GID_BASE + 2
    PI_SLICE = T.get_device_slice(3)
    PI_IFG = T.get_device_ifg(1)
    PI_PIF_FIRST = T.get_device_first_serdes(8)

    SA = T.mac_addr('be:ef:5d:35:7a:30')
    DA = T.mac_addr('01:00:5e:00:00:05')
    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('224.0.0.5')

    OSPF_PACKET_BASE = \
        S.Ether(dst=DA.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=1, proto=89)
    OSPF_PACKET, __ = U.enlarge_packet_to_min_length(OSPF_PACKET_BASE)

    PUNT_V4_PACKET = \
        S.Ether(dst=HOST_MAC_ADDR,
                src=PUNT_INJECT_PORT_MAC_ADDR,
                type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(prio=0,
                id=0,
                vlan=PUNT_VLAN,
                type=U.Ethertype.Punt.value) / \
        U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
               fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
               next_header_offset=22,
               source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_LPTS_FORWARDING,
               code=LPTS_PUNT_CODE_V4,
               source_sp=T.RX_SYS_PORT_GID,
               destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
               source_lp=T.RX_L3_AC_GID,
               # destination_lp=0x7fff,
               destination_lp=nplapi.NPL_REDIRECT_CODE_LPM_LPTS,
               relay_id=T.VRF_GID,
               lpts_flow_type=LPTS_FLOW_TYPE_V4) / \
        OSPF_PACKET

    def setUp(self):
        super().setUp()

        ssch.rechoose_PI_slices(self, self.device)
        # setup inject port
        self.pi_port = T.punt_inject_port(
            self,
            self.device,
            self.PI_SLICE,
            self.PI_IFG,
            self.PI_SP_GID,
            self.PI_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        # setup punt port
        self.punt_dest = T.create_l2_punt_destination(
            self,
            self.device,
            T.L2_PUNT_DESTINATION2_GID,
            self.pi_port,
            HOST_MAC_ADDR,
            PUNT_VLAN)

        # Default is to have both unicast and multicast enabled
        self.topology.rx_l3_ac.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_UC, True)
        self.topology.rx_l3_ac.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_MC, True)

        self.topology.rx_l3_ac.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV6_UC, True)
        self.topology.rx_l3_ac.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV6_MC, True)

        self.lpts_v4 = self.device.create_lpts(sdk.lpts_type_e_LPTS_TYPE_IPV4)
        self.assertNotEqual(self.lpts_v4, None)
        k = sdk.la_lpts_key()
        k.type = sdk.lpts_type_e_LPTS_TYPE_IPV4
        result = sdk.la_lpts_result()
        result.flow_type = LPTS_FLOW_TYPE_V4
        result.punt_code = LPTS_PUNT_CODE_V4
        result.tc = 0
        result.dest = self.punt_dest
        result.counter_or_meter = T.create_meter_set(self, self.device, is_aggregate=True)
        result.meter = None
        self.lpts_v4.append(k, result)

        self.lpts_v6 = self.device.create_lpts(sdk.lpts_type_e_LPTS_TYPE_IPV6)
        k.type = sdk.lpts_type_e_LPTS_TYPE_IPV6
        self.assertNotEqual(self.lpts_v6, None)
        result.flow_type = LPTS_FLOW_TYPE_V6
        result.punt_code = LPTS_PUNT_CODE_V6
        result.counter_or_meter = T.create_meter_set(self, self.device, is_aggregate=True)
        self.lpts_v6.append(k, result)

    def tearDown(self):

        # Ensure the l3_ac is active
        self.topology.rx_l3_ac.hld_obj.set_active(True)

        # Clear the lpts configuration
        self.lpts_v4.clear()
        self.lpts_v6.clear()

        super().tearDown()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_OSPF_over_l3_uc_and_mc_disabled(self):
        '''
          Pass an OSPF packet over L3 AC port.
          Unicast and multicast disable, OSPF should drop
        '''
        self.topology.rx_l3_ac.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_UC, False)
        self.topology.rx_l3_ac.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_MC, False)

        U.run_and_drop(self, self.device, TrapsOSPFOverL3.OSPF_PACKET,
                       T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_OSPF_over_l3_uc_enabled_and_mc_disabled(self):
        '''
          Pass an OSPF packet over L3 AC port.
          Enable Unicast, Multicast disabled, OSPF should be punted
        '''
        self.topology.rx_l3_ac.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_MC, False)

        U.run_and_compare(self, self.device, TrapsOSPFOverL3.OSPF_PACKET,
                          T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          TrapsOSPFOverL3.PUNT_V4_PACKET,
                          self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_OSPF_over_l3_uc_and_mc_enabled(self):
        '''
          Pass an OSPF packet over L3 AC port.
          Unicast and multicast enabled, OSPF should punt
        '''
        U.run_and_compare(self, self.device, TrapsOSPFOverL3.OSPF_PACKET,
                          T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          TrapsOSPFOverL3.PUNT_V4_PACKET,
                          self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_OSPF_over_l3_uc_disabled_mc_enabled(self):
        '''
          Pass an OSPF packet over L3 AC port.
          Unicast disabled, multicast enabled, OSPF should punt
        '''
        self.topology.rx_l3_ac.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV4_UC, False)

        U.run_and_compare(self, self.device, TrapsOSPFOverL3.OSPF_PACKET,
                          T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          TrapsOSPFOverL3.PUNT_V4_PACKET,
                          self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_OSPF_over_l3_ac_disabled(self):
        '''
          Pass an OSPF packet over L3 AC port.
          l3_ac disabled, OSPF should drop
        '''
        # 5. Disabled the l3_ac, OSPF should be dropped
        self.topology.rx_l3_ac.hld_obj.set_active(False)
        U.run_and_drop(self, self.device, TrapsOSPFOverL3.OSPF_PACKET,
                       T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    DA_V6 = T.mac_addr('33:33:00:00:00:05')
    SIP_V6 = T.ipv6_addr('6000::2')
    DIP_V6 = T.ipv6_addr('FF02::5')

    OSPF_V6_PACKET_BASE = \
        S.Ether(dst=DA_V6.addr_str,
                src=SA.addr_str,
                type=U.Ethertype.QinQ.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2) / \
        S.IPv6(src=SIP_V6.addr_str, dst=DIP_V6.addr_str, hlim=1, nh=89)
    OSPF_V6_PACKET, __ = U.enlarge_packet_to_min_length(OSPF_V6_PACKET_BASE)

    PUNT_V6_PACKET = \
        S.Ether(dst=HOST_MAC_ADDR,
                src=PUNT_INJECT_PORT_MAC_ADDR,
                type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(prio=0,
                id=0,
                vlan=PUNT_VLAN,
                type=U.Ethertype.Punt.value) / \
        U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
               fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
               next_header_offset=22,
               source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_LPTS_FORWARDING,
               code=LPTS_PUNT_CODE_V6,
               source_sp=T.RX_SYS_PORT_GID,
               destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
               source_lp=T.RX_L3_AC_GID,
               # destination_lp=0x7fff,
               destination_lp=nplapi.NPL_REDIRECT_CODE_LPM_LPTS,
               relay_id=T.VRF_GID,
               lpts_flow_type=LPTS_FLOW_TYPE_V6) / \
        OSPF_V6_PACKET

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_OSPFv3_over_l3_uc_and_mc_disabled(self):
        '''
          Pass an OSPFv3 IPV6 packet over L3 AC port.
          Unicast and multicast disable, OSPF should drop
        '''
        self.topology.rx_l3_ac.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV6_UC, False)
        self.topology.rx_l3_ac.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV6_MC, False)
        U.run_and_drop(self, self.device, TrapsOSPFOverL3.OSPF_V6_PACKET,
                       T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.get_matilda_model_from_env() == ('3.2A', True), "Test fails non matilda 3.2A boards")
    def test_OSPFv3_over_l3_uc_enabled_mc_disabled(self):
        '''
          Pass an OSPFv3 IPV6 packet over L3 AC port.
          Unicast enabled, multicast disabled, OSPF should punt
        '''
        self.topology.rx_l3_ac.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV6_MC, False)
        U.run_and_compare(self, self.device, TrapsOSPFOverL3.OSPF_V6_PACKET,
                          T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          TrapsOSPFOverL3.PUNT_V6_PACKET,
                          self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.get_matilda_model_from_env() == ('3.2A', True), "Test fails non matilda 3.2A boards")
    def test_OSPFv3_over_l3_uc_and_mc_enabled(self):
        '''
          Pass an OSPFv3 IPV6 packet over L3 AC port.
          Unicast and multicast enabled, OSPF should punt
        '''
        U.run_and_compare(self, self.device, TrapsOSPFOverL3.OSPF_V6_PACKET,
                          T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          TrapsOSPFOverL3.PUNT_V6_PACKET,
                          self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.get_matilda_model_from_env() == ('3.2A', True), "Test fails non matilda 3.2A boards")
    def test_OSPFv3_over_l3_uc_disabled_mc_enabled(self):
        '''
          Pass an OSPFv3 IPV6 packet over L3 AC port.
          Unicast disabled, multicast enabled, OSPF should punt
        '''
        self.topology.rx_l3_ac.hld_obj.set_protocol_enabled(
            sdk.la_l3_protocol_e_IPV6_UC, False)
        U.run_and_compare(self, self.device, TrapsOSPFOverL3.OSPF_V6_PACKET,
                          T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          TrapsOSPFOverL3.PUNT_V6_PACKET,
                          self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.get_matilda_model_from_env() == ('3.2A', True), "Test fails non matilda 3.2A boards")
    def test_OSPFv3_over_l3_ac_disabled(self):
        '''
          Pass an OSPFv3 IPV6 packet over L3 AC port.
          l3_ac disabled, OSPF should drop
        '''
        self.topology.rx_l3_ac.hld_obj.set_active(False)

        U.run_and_drop(self, self.device, TrapsOSPFOverL3.OSPF_V6_PACKET,
                       T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)


if __name__ == '__main__':
    unittest.main()
