#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

from packet_test_utils import *
from scapy.all import *
import unittest
from leaba import sdk
import sim_utils
import ip_test_base
import topology as T
from sdk_test_case_base import *
from collections import namedtuple
from traps_base import *
import decor

SYS_PORT_GID_BASE = 100
AC_PORT_GID_BASE = 200

L2_IFG = 1

L2_FIRST_SERDES = 4
L2_LAST_SERDES = 5

DST_MAC = "ab:fe:aa:ff:bb:dd"
SRC_MAC = "00:ad:00:00:00:00"

VLAN = 0xAB9

PREFIX1_GID = 0x691
LDP_LABEL = sdk.la_mpls_label()
LDP_LABEL.label = 0x64
PWE_LOCAL_LABEL = sdk.la_mpls_label()
PWE_LOCAL_LABEL.label = 0x62
PWE_LOCAL_LABEL1 = sdk.la_mpls_label()
PWE_LOCAL_LABEL1.label = 0x72
PWE_REMOTE_LABEL = sdk.la_mpls_label()
PWE_REMOTE_LABEL.label = 0x63
PWE_REMOTE_LABEL1 = sdk.la_mpls_label()
PWE_REMOTE_LABEL1.label = 0x73
PWE_PORT_GID = 0x292
PWE_PORT_GID1 = 0x293
PWE_GID = 0x82
PWE_GID1 = 0x83
PWE_TTL = 0xff

PRIVATE_DATA_DEFAULT = 0xfedcba9876543210

CFM_DMAC = "1:80:c2:00:00:32"
CFM_ETYPE = 0x8902
CFM_MD_ascii = '\x40'
CFM_OPCODE_ascii = '\x01'
CFM_PDU_ascii = '\x00\x00'

cfm_raw = S.Raw()
cfm_raw.load = CFM_MD_ascii + CFM_OPCODE_ascii + CFM_PDU_ascii

PUNT_BASE_CFM = \
    S.Ether(dst=HOST_MAC_ADDR, src=PUNT_INJECT_PORT_MAC_ADDR, type=Ethertype.Dot1Q.value) / \
    S.Dot1Q(prio=0, id=0, vlan=PUNT_VLAN, type=Ethertype.Punt.value) / \
    Punt(next_header=sdk.la_packet_types.LA_PROTOCOL_TYPE_ETHERNET,
         fwd_header_type=sdk.la_packet_types.LA_HEADER_TYPE_ETHERNET,
         next_header_offset=0,
         source=sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_INGRESS_TRAP,
         code=sdk.LA_EVENT_ETHERNET_TEST_OAM_AC_MEP,
         source_sp=SYS_PORT_GID_BASE,
         destination_sp=sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID,
         source_lp=0x800c9,
         destination_lp=sdk.LA_EVENT_ETHERNET_TEST_OAM_AC_MEP,
         relay_id=0,
         lpts_flow_type=0)

INPUT_PACKET_BASE = \
    S.Ether(dst=DST_MAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
    S.Dot1Q(vlan=VLAN, type=CFM_ETYPE) / \
    cfm_raw

INPUT_PACKET_UNTAGGED_BASE = \
    S.Ether(dst=DST_MAC, src=SRC_MAC, type=CFM_ETYPE) / \
    cfm_raw

INPUT_PACKET_L2CP_BASE = \
    S.Ether(dst=CFM_DMAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
    S.Dot1Q(vlan=VLAN, type=CFM_ETYPE) / \
    cfm_raw

INPUT_PACKET_PWE_BASE = \
    S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
    S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
    S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.MPLS.value) / \
    MPLS(label=PWE_LOCAL_LABEL.label, ttl=PWE_TTL) / \
    S.Ether(dst=DST_MAC, src=SRC_MAC, type=U.Ethertype.Dot1Q.value) / \
    S.Dot1Q(vlan=VLAN, type=CFM_ETYPE) / \
    cfm_raw

INPUT_PACKET_PWE_L2CP_BASE = \
    S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
    S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
    S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.MPLS.value) / \
    MPLS(label=PWE_LOCAL_LABEL.label, ttl=PWE_TTL) / \
    S.Ether(dst=CFM_DMAC, src=SRC_MAC, type=Ethertype.Dot1Q.value) / \
    S.Dot1Q(vlan=VLAN, type=CFM_ETYPE) / \
    cfm_raw

INPUT_PACKET_PWE1_BASE = \
    S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=SA.addr_str, type=U.Ethertype.QinQ.value) / \
    S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID1, type=U.Ethertype.Dot1Q.value) / \
    S.Dot1Q(vlan=T.RX_L3_AC_PORT_VID2, type=U.Ethertype.MPLS.value) / \
    MPLS(label=PWE_LOCAL_LABEL1.label, ttl=PWE_TTL) / \
    S.Ether(dst=DST_MAC, src=SRC_MAC, type=CFM_ETYPE) / \
    cfm_raw

EXPECTED_PACKET_CFM_BASE = \
    S.Ether(dst=DST_MAC, src=SRC_MAC, type=U.Ethertype.Dot1Q.value) / \
    S.Dot1Q(vlan=VLAN, type=CFM_ETYPE) / \
    cfm_raw

EXPECTED_PACKET_CFM_L2CP_BASE = \
    S.Ether(dst=CFM_DMAC, src=SRC_MAC, type=U.Ethertype.Dot1Q.value) / \
    S.Dot1Q(vlan=VLAN, type=CFM_ETYPE) / \
    cfm_raw

INPUT_PACKET, __ = enlarge_packet_to_min_length(INPUT_PACKET_BASE)
INPUT_PACKET_L2CP, __ = enlarge_packet_to_min_length(INPUT_PACKET_L2CP_BASE)
INPUT_PACKET_UNTAGGED, __ = enlarge_packet_to_min_length(INPUT_PACKET_UNTAGGED_BASE)
INPUT_PACKET_PWE, BASE_INPUT_PACKET_PAYLOAD_SIZE = enlarge_packet_to_min_length(INPUT_PACKET_PWE_BASE)
INPUT_PACKET_PWE_L2CP, BASE_INPUT_PACKET_PWE_PAYLOAD_SIZE = enlarge_packet_to_min_length(INPUT_PACKET_PWE_L2CP_BASE)
INPUT_PACKET_PWE1, BASE_INPUT_PACKET_PWE1_PAYLOAD_SIZE = enlarge_packet_to_min_length(INPUT_PACKET_PWE1_BASE)
EXPECTED_PACKET_PWE = INPUT_PACKET_PWE[4]
EXPECTED_PACKET_PWE1 = INPUT_PACKET_PWE1[4]


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class TrapsCFM(sdk_test_case_base):
    # Static members
    phy_port = namedtuple('phy_port', 'slice ifg first_serdes last_serdes sys_port_gid ac_port_gid')
    L2_SLICE = T.get_device_slice(2)
    PI_SLICE = T.get_device_slice(3)

    def setUp(self):
        self.skipTest("an error in initialization of la_l2_service_port in pwe mode")
        return
        # super().setUp(create_default_topology=False)
        super().setUp()
        self.L2_SLICE = T.choose_active_slices(self.device, self.L2_SLICE, [2, 4])
        self.PI_SLICE = T.choose_active_slices(self.device, self.PI_SLICE, [3, 1])
        self.ports = [
            self.phy_port(
                self.L2_SLICE,
                L2_IFG,
                L2_FIRST_SERDES,
                L2_LAST_SERDES,
                SYS_PORT_GID_BASE,
                AC_PORT_GID_BASE),
            self.phy_port(
                self.L2_SLICE,
                L2_IFG,
                L2_FIRST_SERDES + 2,
                L2_LAST_SERDES + 2,
                SYS_PORT_GID_BASE + 1,
                AC_PORT_GID_BASE + 1),
            self.phy_port(
                self.L2_SLICE,
                L2_IFG,
                L2_FIRST_SERDES + 4,
                L2_LAST_SERDES + 4,
                SYS_PORT_GID_BASE + 2,
                AC_PORT_GID_BASE + 2),
            self.phy_port(
                self.L2_SLICE,
                L2_IFG,
                L2_FIRST_SERDES + 6,
                L2_LAST_SERDES + 6,
                SYS_PORT_GID_BASE + 3,
                AC_PORT_GID_BASE + 3),
            self.phy_port(
                self.L2_SLICE,
                L2_IFG,
                L2_FIRST_SERDES + 8,
                L2_LAST_SERDES + 8,
                SYS_PORT_GID_BASE + 4,
                AC_PORT_GID_BASE + 4),
            self.phy_port(
                self.L2_SLICE,
                L2_IFG,
                L2_FIRST_SERDES + 10,
                L2_LAST_SERDES + 10,
                SYS_PORT_GID_BASE + 10,
                AC_PORT_GID_BASE + 5)]

        self.ip_impl = ip_test_base.ipv4_test_base()
        self.l3_port_impl = T.ip_l3_ac_base(self.topology)

        self.create_network_topology()

        self.add_default_route()

        self.pi_port = T.punt_inject_port(
            self,
            self.device,
            self.PI_SLICE,
            TrapsTest.PI_IFG,
            TrapsTest.PI_SP_GID,
            TrapsTest.PI_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        self.punt_dest = T.create_l2_punt_destination(
            self,
            self.device,
            T.L2_PUNT_DESTINATION2_GID,
            self.pi_port,
            HOST_MAC_ADDR,
            PUNT_VLAN)

        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_TEST_OAM_AC_MEP, 0, None, self.punt_dest, False, False, True, 0)

    def add_default_route(self):
        prefix = self.ip_impl.get_default_prefix()
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.def_nh, PRIVATE_DATA_DEFAULT)

    def tearDown(self):
        self.destroy_ports()
        super().tearDown()

    def create_network_topology(self):
        self.create_ecmp_to_mpls()
        self.create_ports()

    def create_ac_port(self, num, vlan_tag):
        self.eth_ports.insert(
            num,
            T.ethernet_port(
                self,
                self.device,
                self.ports[num].slice,
                self.ports[num].ifg,
                self.ports[num].sys_port_gid,
                self.ports[num].first_serdes,
                self.ports[num].last_serdes))
        self.eth_ports[num].set_ac_profile(self.ac_profile)
        self.ac_ports.insert(num,
                             T.l2_ac_port(self, self.device,
                                          self.ports[num].ac_port_gid,
                                          self.topology.filter_group_def,
                                          None,
                                          self.eth_ports[num],
                                          None, vlan_tag, 0x0))

    def create_ports(self):
        self.eth_ports = []
        self.ac_ports = []

        self.ac_profile = T.ac_profile(self, self.device)

        # Tagged ports
        for i in range(6):
            if i < 3:
                # Tagged ports
                self.create_ac_port(i, VLAN)
            else:
                # Untagged ports
                self.create_ac_port(i, 0)

        self._l2_p2p_attach(0, 1)
        self._l2_p2p_attach(3, 4)

        self.pwe_port = T.l2_pwe_port(self, self.device, PWE_PORT_GID, PWE_LOCAL_LABEL,
                                      PWE_REMOTE_LABEL, PWE_GID, self.pfx_obj.hld_obj)
        self.pwe_port.hld_obj.set_ac_profile_for_pwe(self.ac_profile.hld_obj)
        self.pwe_port.hld_obj.set_destination(self.ac_ports[2].hld_obj)

        self.pwe_port1 = T.l2_pwe_port(self, self.device, PWE_PORT_GID1, PWE_LOCAL_LABEL1,
                                       PWE_REMOTE_LABEL1, PWE_GID1, self.pfx_obj.hld_obj)
        self.pwe_port1.hld_obj.set_ac_profile_for_pwe(self.ac_profile.hld_obj)
        self.pwe_port1.hld_obj.set_destination(self.ac_ports[5].hld_obj)

    def create_p2p_destination(self, first_port, second_port):
        self.ac_ports[first_port].hld_obj.set_destination(self.ac_ports[second_port].hld_obj)
        self.ac_ports[second_port].hld_obj.set_destination(self.ac_ports[first_port].hld_obj)

    def create_ecmp_to_mpls(self):
        nh_ecmp = self.device.create_ecmp_group(sdk.la_ecmp_group.level_e_LEVEL_2)
        self.assertNotEqual(nh_ecmp, None)
        nh_ecmp.add_member(self.l3_port_impl.reg_nh.hld_obj)

        self.pfx_obj = T.prefix_object(self, self.device, PREFIX1_GID, nh_ecmp)
        self.assertNotEqual(self.pfx_obj.hld_obj, None)

        lsp_labels = []
        lsp_labels.append(LDP_LABEL)

        self.pfx_obj.hld_obj.set_nh_lsp_properties(
            self.l3_port_impl.reg_nh.hld_obj,
            lsp_labels,
            None,
            sdk.la_prefix_object.lsp_counter_mode_e_LABEL)

    def destroy_ports(self):
        for ac_port in self.ac_ports:
            ac_port.hld_obj.detach()

        self.pwe_port.hld_obj.detach()
        self.pwe_port1.hld_obj.detach()

        for ac_port in self.ac_ports:
            ac_port.destroy()

        self.pwe_port.destroy()
        self.pwe_port1.destroy()

        for eth_port in self.eth_ports:
            eth_port.destroy()

        self.ac_profile.destroy()

    def _l2_p2p_attach(self, ingress_port_num, egress_port_num):
        self.create_p2p_destination(ingress_port_num, egress_port_num)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_cfm_l2ac_down_mep_enabled(self):
        self.ac_ports[0].hld_obj.set_cfm_enabled(sdk.la_mep_direction_e_DOWN, 2)

        PUNT_PACKET = PUNT_BASE_CFM / INPUT_PACKET

        # Packet should trap and punt
        run_and_compare(self, self.device,
                        INPUT_PACKET, self.L2_SLICE, L2_IFG, self.ports[0].first_serdes,
                        PUNT_PACKET, self.PI_SLICE, TrapsTest.PI_IFG, TrapsTest.PI_PIF_FIRST)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_cfm_l2ac_down_mep_disabled(self):
        self.ac_ports[0].hld_obj.set_cfm_enabled(sdk.la_mep_direction_e_DOWN, 2)
        self.ac_ports[0].hld_obj.clear_cfm(sdk.la_mep_direction_e_DOWN)

        # Packet should get forwarded
        run_and_compare(self, self.device,
                        INPUT_PACKET, self.L2_SLICE, L2_IFG, self.ports[0].first_serdes,
                        INPUT_PACKET, self.L2_SLICE, L2_IFG, self.ports[1].first_serdes)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_cfm_l2ac_down_mep_md_level_mismatch(self):
        self.ac_ports[0].hld_obj.set_cfm_enabled(sdk.la_mep_direction_e_DOWN, 1)

        # Packet should get forwarded
        run_and_compare(self, self.device,
                        INPUT_PACKET, self.L2_SLICE, L2_IFG, self.ports[0].first_serdes,
                        INPUT_PACKET, self.L2_SLICE, L2_IFG, self.ports[1].first_serdes)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_cfm_l2ac_down_mep_l2cp(self):
        self.ac_ports[0].hld_obj.set_cfm_enabled(sdk.la_mep_direction_e_DOWN, 2)

        PUNT_PACKET = PUNT_BASE_CFM / INPUT_PACKET_L2CP

        # Packet should trap and punt
        run_and_compare(self, self.device,
                        INPUT_PACKET_L2CP, self.L2_SLICE, L2_IFG, self.ports[0].first_serdes,
                        PUNT_PACKET, self.PI_SLICE, TrapsTest.PI_IFG, TrapsTest.PI_PIF_FIRST)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_cfm_l2ac_down_mep_untagged_enabled(self):
        self.ac_ports[3].hld_obj.set_cfm_enabled(sdk.la_mep_direction_e_DOWN, 2)
        PUNT_BASE_CFM.source_sp = self.ports[3].sys_port_gid
        PUNT_BASE_CFM.source_lp = 0x800cc

        PUNT_PACKET = PUNT_BASE_CFM / INPUT_PACKET_UNTAGGED

        # Packet should trap and punt
        run_and_compare(self, self.device,
                        INPUT_PACKET_UNTAGGED, self.L2_SLICE, L2_IFG, self.ports[3].first_serdes,
                        PUNT_PACKET, self.PI_SLICE, TrapsTest.PI_IFG, TrapsTest.PI_PIF_FIRST)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_cfm_l2ac_down_mep_untagged_disabled(self):

        # Packet should trap and punt
        run_and_compare(self, self.device,
                        INPUT_PACKET_UNTAGGED, self.L2_SLICE, L2_IFG, self.ports[3].first_serdes,
                        INPUT_PACKET_UNTAGGED, self.L2_SLICE, L2_IFG, self.ports[4].first_serdes)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_cfm_l2ac_down_mep_untagged_md_level_mismatch(self):
        self.ac_ports[3].hld_obj.set_cfm_enabled(sdk.la_mep_direction_e_DOWN, 1)

        # Packet should trap and punt
        run_and_compare(self, self.device,
                        INPUT_PACKET_UNTAGGED, self.L2_SLICE, L2_IFG, self.ports[3].first_serdes,
                        INPUT_PACKET_UNTAGGED, self.L2_SLICE, L2_IFG, self.ports[4].first_serdes)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    def test_cfm_pwe_up_mep(self):
        self.ac_ports[2].hld_obj.set_cfm_enabled(sdk.la_mep_direction_e_UP, 2)
        PUNT_BASE_CFM.source = sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_EGRESS_TRAP
        PUNT_BASE_CFM.source_sp = sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID
        PUNT_BASE_CFM.destination_sp = self.ports[2].sys_port_gid
        PUNT_BASE_CFM.source_lp = 0x80000
        PUNT_BASE_CFM.destination_lp = self.ports[2].ac_port_gid

        EXPECTED_PACKET = U.add_payload(EXPECTED_PACKET_CFM_BASE, BASE_INPUT_PACKET_PAYLOAD_SIZE)
        PUNT_PACKET = PUNT_BASE_CFM / EXPECTED_PACKET

        # Packet should trap and punt
        run_and_compare(self, self.device,
                        INPUT_PACKET_PWE, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        PUNT_PACKET, self.PI_SLICE, TrapsTest.PI_IFG, TrapsTest.PI_PIF_FIRST)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    def test_cfm_pwe_up_mep_disabled(self):
        self.ac_ports[2].hld_obj.set_cfm_enabled(sdk.la_mep_direction_e_UP, 2)
        self.ac_ports[2].hld_obj.clear_cfm(sdk.la_mep_direction_e_UP)

        # Packet should trap and punt
        run_and_compare(self, self.device,
                        INPUT_PACKET_PWE, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        EXPECTED_PACKET_PWE, self.L2_SLICE, L2_IFG, self.ports[2].first_serdes)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    def test_cfm_pwe_up_mep_md_level_mismatch(self):
        self.ac_ports[2].hld_obj.set_cfm_enabled(sdk.la_mep_direction_e_UP, 1)

        # Packet should trap and punt
        run_and_compare(self, self.device,
                        INPUT_PACKET_PWE, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        EXPECTED_PACKET_PWE, self.L2_SLICE, L2_IFG, self.ports[2].first_serdes)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    def test_cfm_pwe_up_mep_l2cp(self):
        self.ac_ports[2].hld_obj.set_cfm_enabled(sdk.la_mep_direction_e_UP, 2)
        PUNT_BASE_CFM.source = sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_EGRESS_TRAP
        PUNT_BASE_CFM.source_sp = sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID
        PUNT_BASE_CFM.destination_sp = self.ports[2].sys_port_gid
        PUNT_BASE_CFM.source_lp = 0x80000
        PUNT_BASE_CFM.destination_lp = self.ports[2].ac_port_gid

        EXPECTED_PACKET = U.add_payload(EXPECTED_PACKET_CFM_L2CP_BASE, BASE_INPUT_PACKET_PWE_PAYLOAD_SIZE)
        PUNT_PACKET = PUNT_BASE_CFM / EXPECTED_PACKET

        # Packet should trap and punt
        run_and_compare(self, self.device,
                        INPUT_PACKET_PWE_L2CP, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        PUNT_PACKET, self.PI_SLICE, TrapsTest.PI_IFG, TrapsTest.PI_PIF_FIRST)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    def test_cfm_pwe_up_mep_untagged(self):
        self.ac_ports[5].hld_obj.set_cfm_enabled(sdk.la_mep_direction_e_UP, 2)
        PUNT_BASE_CFM.source = sdk.la_packet_types.LA_PACKET_PUNT_SOURCE_EGRESS_TRAP
        PUNT_BASE_CFM.source_sp = sdk.la_packet_types.LA_SYSTEM_PORT_GID_INVALID
        PUNT_BASE_CFM.destination_sp = self.ports[5].sys_port_gid
        PUNT_BASE_CFM.source_lp = 0x80000
        PUNT_BASE_CFM.destination_lp = self.ports[5].ac_port_gid

        EXPECTED_PACKET = U.add_payload(INPUT_PACKET_UNTAGGED_BASE, BASE_INPUT_PACKET_PWE1_PAYLOAD_SIZE)
        PUNT_PACKET = PUNT_BASE_CFM / EXPECTED_PACKET

        # Packet should trap and punt
        run_and_compare(self, self.device,
                        INPUT_PACKET_PWE1, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        PUNT_PACKET, self.PI_SLICE, TrapsTest.PI_IFG, TrapsTest.PI_PIF_FIRST)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    def test_cfm_pwe_up_mep_untagged_disabled(self):

        # Packet should trap and punt
        run_and_compare(self, self.device,
                        INPUT_PACKET_PWE1, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        EXPECTED_PACKET_PWE1, self.L2_SLICE, L2_IFG, self.ports[5].first_serdes)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    def test_cfm_pwe_up_mep_untagged_md_level_mismatch(self):
        self.ac_ports[5].hld_obj.set_cfm_enabled(sdk.la_mep_direction_e_UP, 1)

        # Packet should trap and punt
        run_and_compare(self, self.device,
                        INPUT_PACKET_PWE1, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                        EXPECTED_PACKET_PWE1, self.L2_SLICE, L2_IFG, self.ports[5].first_serdes)


if __name__ == '__main__':
    unittest.main()
