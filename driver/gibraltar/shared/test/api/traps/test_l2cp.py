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

import unittest
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import topology as T
import sim_utils
import nplapicli as nplapi

from traps_base import *
import smart_slices_choise as ssch
import decor

TEST_L2CP_INDEX = 0
TEST_CFM_INDEX = 1
DMAC = T.mac_addr('01:80:c2:00:00:50')
MASK = T.mac_addr('ff:ff:ff:ff:ff:f8')  # Mask match lsb 00 - 07
CFM_DMAC = T.mac_addr('01:80:c2:00:00:31')
CFM_MASK = T.mac_addr('ff:ff:ff:ff:ff:ff')
CFM_ETYPE = 0x8902

CFM_MD_ascii = '\x00'
CFM_MD_lvl1_ascii = '\x20'
CFM_OPCODE_ascii = '\x01'
CFM_PDU_ascii = '\x00\x00'

cfm_raw = S.Raw()
cfm_raw.load = CFM_MD_ascii + CFM_OPCODE_ascii + CFM_PDU_ascii

cfm_raw_lvl1 = S.Raw()
cfm_raw_lvl1.load = CFM_MD_lvl1_ascii + CFM_OPCODE_ascii + CFM_PDU_ascii

PUNT_RELAY_ID = 0 if decor.is_pacific() else T.VRF_GID
PUNT_BASE = \
    S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
    S.Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
    U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
           fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
           next_header_offset=0,
           source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
           code=sdk.LA_EVENT_ETHERNET_L2CP0,
           source_sp=T.RX_SYS_PORT_GID,
           destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
           source_lp=T.RX_L2_AC_PORT_GID | nplapi.NPL_PUNT_HEADER_L2_SLP_ENCODING,
           destination_lp=sdk.LA_EVENT_ETHERNET_L2CP0,
           relay_id=PUNT_RELAY_ID,
           lpts_flow_type=0)

PUNT_BASE_CFM = \
    S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=U.Ethertype.Dot1Q.value) / \
    S.Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=U.Ethertype.Punt.value) / \
    U.Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
           fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
           next_header_offset=0,
           source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
           code=sdk.LA_EVENT_ETHERNET_L2CP1,
           source_sp=T.TX_L3_AC_SYS_PORT_REG_GID,
           destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
           source_lp=T.TX_L3_AC_REG_GID,
           destination_lp=sdk.LA_EVENT_ETHERNET_L2CP1,
           relay_id=0,
           lpts_flow_type=0)

INPUT_PACKET_BASE = \
    S.Ether(dst=DMAC.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
    S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1, type=U.Ethertype.LLDP.value)

INPUT_PACKET_CFM_BASE = \
    S.Ether(dst=T.TX_L3_AC_REG_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
    S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1, type=CFM_ETYPE)

INPUT_PACKET_CFM_L2AC_BASE = \
    S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
    S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
    S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID2, type=CFM_ETYPE)


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class TrapsL2CP(unittest.TestCase):
    l2cp_config_entry_list = []
    PI_SP_GID = TrapsTest.PI_SP_GID
    PI_SLICE = TrapsTest.PI_SLICE
    PI_IFG = TrapsTest.PI_IFG
    PI_PIF_FIRST = TrapsTest.PI_PIF_FIRST

    def setUp(self):

        self.maxDiff = None  # Show whole strings on failures (unittest variable)
        self.device = sim_utils.create_device(1)
        self.topology = T.topology(self, self.device)
        ssch.rechoose_PI_slices(self, self.device)

        self.pi_port = T.punt_inject_port(
            self,
            self.device,
            self.PI_SLICE,
            self.PI_IFG,
            self.PI_SP_GID,
            self.PI_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        self.punt_dest = T.create_l2_punt_destination(
            self,
            self.device,
            T.L2_PUNT_DESTINATION2_GID,
            self.pi_port,
            HOST_MAC_ADDR,
            PUNT_VLAN)

        self.topology.rx_switch.hld_obj.set_mac_entry(
            DMAC.hld_obj,
            self.topology.tx_l2_ac_port_reg.hld_obj,
            sdk.LA_MAC_AGING_TIME_NEVER)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_L2CP0, 0, None, self.punt_dest, False, False, True, 0)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_L2CP1, 0, None, self.punt_dest, False, False, True, 0)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_TEST_OAM_CFM_LINK_MDL0,
                                           0, None, self.punt_dest, False, False, True, 0)
        self.copc_mac = self.device.create_copc(sdk.la_control_plane_classifier.type_e_MAC)

    def tearDown(self):
        self.device.tearDown()
        self.topology = None

    def install_l2cp_entry_in_copc_mac_table(
            self,
            ether_value,
            ether_mask,
            mac_da,
            npp_attribute,
            is_l2cp0=True):

        key1 = []
        f1 = sdk.field()
        f1.type.mac = sdk.la_control_plane_classifier.mac_field_type_e_ETHERNET_PROFILE_ID
        f1.val.mac.ethernet_profile_id = npp_attribute
        f1.mask.mac.ethernet_profile_id = npp_attribute
        key1.append(f1)

        f2 = sdk.field()
        f2.type.mac = sdk.la_control_plane_classifier.mac_field_type_e_DA
        f2.val.mac.da = mac_da.hld_obj
        f2.mask.mac.da.flat = 0xffffffffffff
        key1.append(f2)

        f3 = sdk.field()
        f3.type.mac = sdk.la_control_plane_classifier.mac_field_type_e_ETHERTYPE
        f3.val.mac.ethertype = ether_value
        f3.mask.mac.ethertype = ether_mask
        key1.append(f3)

        result1 = sdk.result()
        result1.event = sdk.LA_EVENT_ETHERNET_L2CP1
        if is_l2cp0 is True:
            result1.event = sdk.LA_EVENT_ETHERNET_L2CP0

        self.copc_mac.append(key1, result1)

    def clear_entries_from_copc_mac_table(self):
        self.copc_mac.clear()

    def install_default_l2cp_entry(self, mac_da):
        ether_value = U.Ethertype.LLDP.value
        ether_mask = 0xffff
        npp_attribute = 0x1
        self.install_l2cp_entry_in_copc_mac_table(ether_value, ether_mask, mac_da, npp_attribute)

    def enable_l2cp_default(self):
        npp_attribute = 0x1
        self.topology.rx_eth_port.hld_obj.set_copc_profile(npp_attribute)
        prof_val = self.topology.rx_eth_port.hld_obj.get_copc_profile()
        self.assertEqual(prof_val, npp_attribute)

    def enable_l2cp(self, mac_da):
        self.install_default_l2cp_entry(mac_da)
        npp_attribute = 0x1
        self.topology.rx_eth_port.hld_obj.set_copc_profile(npp_attribute)
        prof_val = self.topology.rx_eth_port.hld_obj.get_copc_profile()
        self.assertEqual(prof_val, npp_attribute)

    def install_cfm_entry(self, npp_attribute, mac_da):
        ether_value = CFM_ETYPE
        ether_mask = 0xffff
        self.install_l2cp_entry_in_copc_mac_table(ether_value, ether_mask, mac_da, npp_attribute, False)

    def enable_cfm(self, mac_da):
        npp_attribute = 0x2
        self.install_cfm_entry(npp_attribute, mac_da)
        self.topology.tx_l3_ac_eth_port_reg.hld_obj.set_copc_profile(npp_attribute)
        prof_val = self.topology.tx_l3_ac_eth_port_reg.hld_obj.get_copc_profile()
        self.assertEqual(prof_val, npp_attribute)

    def enable_lldp_and_cfm_entry(self, mac_da):
        npp_attribute = 0x2
        self.install_default_l2cp_entry(mac_da)
        self.install_cfm_entry(npp_attribute, mac_da)
        self.topology.tx_l3_ac_eth_port_reg.hld_obj.set_copc_profile(0x3)
        prof_val = self.topology.tx_l3_ac_eth_port_reg.hld_obj.get_copc_profile()
        self.assertEqual(prof_val, 0x3)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_default_state(self):
        ''' Check default state is disabled. Packet is not trapped
        '''
        self.install_default_l2cp_entry(DMAC)
        prof_val = self.topology.rx_eth_port.hld_obj.get_copc_profile()
        self.assertEqual(prof_val, 0)

        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        # Packet should pass since L2CP trap is disabled
        U.run_and_compare(self, self.device,
                          INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          INPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES)
        self.clear_entries_from_copc_mac_table()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2cp_dmac_match(self):
        ''' Test DMAC LSB in range 00-07 l2cp should trap
        '''

        # Packet should get punt for LSB range 00 - 07
        for mac_lsb in range(8):
            INPUT_PACKET_BASE.dst = INPUT_PACKET_BASE.dst[:-1] + str(mac_lsb)
            INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
            PUNT_PACKET = PUNT_BASE / INPUT_PACKET
            PUNT_PACKET.relay_id = 0
            self.enable_l2cp(T.mac_addr(INPUT_PACKET_BASE.dst))

            U.run_and_compare(self, self.device,
                              INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                              PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

            self.clear_entries_from_copc_mac_table()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2cp_dmac_nomatch(self):
        ''' Test DMAC LSB 09 l2cp shouldn't trap
        '''

        self.enable_l2cp(DMAC)
        # Packet should be forwarded for LSB 09
        INPUT_PACKET_BASE.dst = INPUT_PACKET_BASE.dst[:-1] + str(9)
        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
        self.topology.rx_switch.hld_obj.set_mac_entry(
            T.mac_addr(INPUT_PACKET_BASE.dst).hld_obj,
            self.topology.tx_l2_ac_port_reg.hld_obj,
            sdk.LA_MAC_AGING_TIME_NEVER)

        U.run_and_compare(self, self.device,
                          INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          INPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES)

        self.clear_entries_from_copc_mac_table()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2cp_etype_nomatch(self):
        '''8808/8809 Etype is not trapped
        '''
        self.enable_l2cp(DMAC)
        INPUT_PACKET_BASE = \
            S.Ether(dst=DMAC.addr_str, src=SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
            S.Dot1Q(vlan=T.RX_L2_AC_PORT_VID1, type=U.Ethertype.FlowControl.value)
        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        # Packet should pass instead of trap, since this is not a configured Etype
        U.run_and_compare(self, self.device,
                          INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          INPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_DEF, T.FIRST_SERDES)

        self.clear_entries_from_copc_mac_table()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2cp_etype(self):
        ''' Test matching Etypes supported
        '''
        supported_etypes = [
            # U.Ethertype.IPv4.value, missing last 16 bits in the punted packet ipv4 header. Need to try with good packet
            U.Ethertype.IPv6.value,
            U.Ethertype.Dot1Q.value,
            U.Ethertype.SVLAN.value,
            U.Ethertype.PortExtender.value,
            U.Ethertype.LLDP.value,
            U.Ethertype.FlowControl.value]

        DMAC = T.mac_addr('01:80:c2:00:00:50')
        MASK = T.mac_addr('ff:ff:ff:ff:ff:ff')  # Mask match all 48 bits

        npp_attribute = 0x1
        self.topology.rx_eth_port.hld_obj.set_copc_profile(npp_attribute)
        ether_mask = 0xffff

        for etype in supported_etypes:
            INPUT_PACKET_BASE[1].type = etype
            INPUT_PACKET_BASE.dst = '01:80:c2:00:00:50'
            INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
            PUNT_PACKET = PUNT_BASE / INPUT_PACKET
            PUNT_PACKET.relay_id = 0
            self.install_l2cp_entry_in_copc_mac_table(etype, ether_mask, DMAC, npp_attribute)

            U.run_and_compare(self, self.device,
                              INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                              PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

            self.clear_entries_from_copc_mac_table()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_cfm_match(self):
        '''Cfm packet is trapped
        '''
        self.enable_cfm(CFM_DMAC)
        INPUT_PACKET_BASE = S.Ether(dst=CFM_DMAC.addr_str, src=SA.addr_str, type=CFM_ETYPE) / cfm_raw_lvl1
        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
        PUNT_PACKET = PUNT_BASE_CFM / INPUT_PACKET
        PUNT_PACKET.relay_id = PUNT_RELAY_ID

        # Packet should trap and punt
        U.run_and_compare(self, self.device,
                          INPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        self.clear_entries_from_copc_mac_table()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_cfm_ucast_lvl0(self):
        '''Cfm packet is trapped
        '''
        INPUT_PACKET_CFM_LVL0_BASE = INPUT_PACKET_CFM_BASE / cfm_raw
        INPUT_PACKET_CFM_LVL0, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_CFM_LVL0_BASE)
        PUNT_PACKET = PUNT_BASE_CFM / INPUT_PACKET_CFM_LVL0
        PUNT_PACKET.code = sdk.LA_EVENT_ETHERNET_TEST_OAM_CFM_LINK_MDL0
        PUNT_PACKET.source_lp = 0
        PUNT_PACKET.destination_lp = sdk.LA_EVENT_ETHERNET_TEST_OAM_CFM_LINK_MDL0

        # Packet should trap and punt
        U.run_and_compare(self, self.device,
                          INPUT_PACKET_CFM_LVL0, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_cfm_l2cp_lvl0(self):
        '''Cfm packet is trapped
        '''
        INPUT_PACKET_CFM_LVL0_BASE = INPUT_PACKET_CFM_BASE / cfm_raw
        INPUT_PACKET_CFM_LVL0_BASE[Ether].dst = CFM_DMAC.addr_str
        INPUT_PACKET_CFM_LVL0, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_CFM_LVL0_BASE)
        PUNT_PACKET = PUNT_BASE_CFM / INPUT_PACKET_CFM_LVL0
        PUNT_PACKET.code = sdk.LA_EVENT_ETHERNET_TEST_OAM_CFM_LINK_MDL0
        PUNT_PACKET.source_lp = 0
        PUNT_PACKET.destination_lp = sdk.LA_EVENT_ETHERNET_TEST_OAM_CFM_LINK_MDL0

        # Packet should trap and punt
        U.run_and_compare(self, self.device,
                          INPUT_PACKET_CFM_LVL0, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_cfm_ucast_l2ac_lvl0(self):
        '''Cfm packet is trapped
        '''
        INPUT_PACKET_CFM_L2AC_LVL0_BASE = INPUT_PACKET_CFM_L2AC_BASE / cfm_raw
        INPUT_PACKET_CFM_L2AC_LVL0, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_CFM_L2AC_LVL0_BASE)
        PUNT_PACKET = PUNT_BASE_CFM / INPUT_PACKET_CFM_L2AC_LVL0
        PUNT_PACKET.code = sdk.LA_EVENT_ETHERNET_TEST_OAM_CFM_LINK_MDL0
        PUNT_PACKET.source_sp = T.RX_SYS_PORT_GID
        PUNT_PACKET.source_lp = 0
        PUNT_PACKET.destination_lp = sdk.LA_EVENT_ETHERNET_TEST_OAM_CFM_LINK_MDL0

        # Packet should trap and punt
        U.run_and_compare(self, self.device,
                          INPUT_PACKET_CFM_L2AC_LVL0, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_cfm_ucast_lvl1_drop(self):
        '''Cfm packet is dropped as non level0 unicast punts on L3 AC are not supported
        '''
        INPUT_PACKET_CFM_LVL1_BASE = INPUT_PACKET_CFM_BASE / cfm_raw_lvl1
        INPUT_PACKET_CFM_LVL1, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_CFM_LVL1_BASE)

        # Packet should drop
        U.run_and_drop(self, self.device,
                       INPUT_PACKET_CFM_LVL1, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_cfm_notenabled(self):
        '''Cfm packet is dropped as CFM profile is not enabled on the port
        '''
        npp_attribute = 0x2
        self.install_cfm_entry(npp_attribute, CFM_DMAC)
        INPUT_PACKET_BASE = S.Ether(dst=CFM_DMAC.addr_str, src=SA.addr_str, type=CFM_ETYPE) / cfm_raw_lvl1
        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)

        # Packet should drop
        U.run_and_drop(self, self.device,
                       INPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        self.clear_entries_from_copc_mac_table()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_lldp_and_cfm_match(self):
        '''Cfm and LLDP packets are trapped
        '''

        # LLDP Packet should trap and punt
        INPUT_PACKET_BASE = S.Ether(dst=DMAC.addr_str, src=SA.addr_str, type=U.Ethertype.LLDP.value)
        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
        PUNT_BASE.source_sp = T.TX_L3_AC_SYS_PORT_REG_GID
        PUNT_BASE.source_lp = T.TX_L3_AC_REG_GID
        PUNT_PACKET = PUNT_BASE / INPUT_PACKET
        self.enable_lldp_and_cfm_entry(DMAC)

        U.run_and_compare(self, self.device,
                          INPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        self.clear_entries_from_copc_mac_table()

        # CFM Packet should trap and punt
        INPUT_PACKET_BASE = S.Ether(dst=CFM_DMAC.addr_str, src=SA.addr_str, type=CFM_ETYPE) / cfm_raw_lvl1
        INPUT_PACKET, __ = U.enlarge_packet_to_min_length(INPUT_PACKET_BASE)
        PUNT_PACKET = PUNT_BASE_CFM / INPUT_PACKET
        self.enable_lldp_and_cfm_entry(CFM_DMAC)

        PUNT_PACKET.relay_id = PUNT_RELAY_ID
        # Packet should trap and punt
        U.run_and_compare(self, self.device,
                          INPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, T.FIRST_SERDES_L3_REG,
                          PUNT_PACKET, self.PI_SLICE, self.PI_IFG, self.PI_PIF_FIRST)

        self.clear_entries_from_copc_mac_table()

    def check_equal(self, l2cp_config_entry1, l2cp_config_entry2):
        self.assertEqual(l2cp_config_entry1.val.da.flat, l2cp_config_entry2.val.da.flat)
        self.assertEqual(l2cp_config_entry1.mask.da.flat, l2cp_config_entry2.mask.da.flat)
        self.assertEqual(l2cp_config_entry1.val.ethtype, l2cp_config_entry2.val.ethtype)
        self.assertEqual(l2cp_config_entry1.mask.ethtype, l2cp_config_entry2.mask.ethtype)


if __name__ == '__main__':
    unittest.main()
