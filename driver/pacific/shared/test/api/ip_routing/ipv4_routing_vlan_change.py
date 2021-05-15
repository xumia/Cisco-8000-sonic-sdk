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
from leaba import sdk
from packet_test_utils import *
import scapy.all as S
import sim_utils
import topology as T
from ip_routing_base import *
from sdk_test_case_base import *

SET_SIZE = 2
BASE_VSC = 112
DEST_SLICE = 0
DEST_IFG = 1

NETWORK_SLICES = 6
VSC_SLICE_STEP = 16
VSC_DEVICE_STEP = NETWORK_SLICES * VSC_SLICE_STEP

SPA_L3AC_GID = 3399
SLICE = T.get_device_slice(3)
IFG = 0
FIRST_SERDES1 = T.get_device_first_serdes(4)
LAST_SERDES1 = T.get_device_last_serdes(5)


class ipv4_routing_vlan_change(sdk_test_case_base):
    l3_ac = []

    RX_AC_PORT_GID = 0xabc
    RX_AC_PORT_VID1 = 0x987
    RX_AC_PORT_VID2 = 0x654
    TX_AC_PORT_VID1 = 0x988
    TX_AC_PORT_VID2 = 0x655

    DUMMY_VID2 = 0x321
    DST_MAC = "00:fe:ca:fe:ca:fe"
    SRC_MAC = "00:ad:de:ad:de:ad"

    RX_SYS_PORT_GID = 0x13
    RX_SERDES_FIRST = 2
    RX_SERDES_LAST = 3

    SIP = T.ipv4_addr('12.10.12.10')
    DIP = T.ipv4_addr('82.81.95.250')

    INPUT_PACKET_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=ip_routing_base.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=RX_AC_PORT_VID1) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_routing_base.TTL)

    INPUT_PACKET_QINQ_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=ip_routing_base.SA.addr_str, type=0x9100) / \
        S.Dot1Q(vlan=DUMMY_VID2, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=RX_AC_PORT_VID1) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_routing_base.TTL)

    INPUT_PACKET_DOT1Q_NEW_BASE = \
        S.Ether(dst=T.RX_L3_AC_MAC.addr_str, src=ip_routing_base.SA.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=DUMMY_VID2) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_routing_base.TTL)

    EXPECTED_OUTPUT_PACKET_BASE = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=TX_AC_PORT_VID1) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_routing_base.TTL - 1)

    EXPECTED_OUTPUT_PACKET_DOT1Q_NEW_BASE = \
        S.Ether(dst=T.NH_L3_AC_REG_MAC.addr_str, src=T.TX_L3_AC_REG_MAC.addr_str, type=U.Ethertype.Dot1Q.value) / \
        S.Dot1Q(vlan=DUMMY_VID2) / \
        S.IP(src=SIP.addr_str, dst=DIP.addr_str, ttl=ip_routing_base.TTL - 1)

    INPUT_PACKET, PAYLOAD_SIZE = enlarge_packet_to_min_length(INPUT_PACKET_BASE)
    INPUT_PACKET_QINQ = add_payload(INPUT_PACKET_QINQ_BASE, PAYLOAD_SIZE)
    INPUT_PACKET_DOT1Q_NEW = add_payload(INPUT_PACKET_DOT1Q_NEW_BASE, PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET = add_payload(EXPECTED_OUTPUT_PACKET_BASE, PAYLOAD_SIZE)
    EXPECTED_OUTPUT_PACKET_DOT1Q_NEW = add_payload(EXPECTED_OUTPUT_PACKET_DOT1Q_NEW_BASE, PAYLOAD_SIZE)

    @classmethod
    def setUpClass(cls):
        super(ipv4_routing_vlan_change, cls).setUpClass()
        cls.ip_impl_class = ip_test_base.ipv4_test_base
        cls.ip_impl = cls.ip_impl_class()
        cls.rx_eth_port = T.ethernet_port(
            cls.device,
            T.RX_SLICE,
            T.RX_IFG,
            cls.RX_SYS_PORT_GID,
            cls.RX_SERDES_FIRST,
            cls.RX_SERDES_LAST)

        cls.tx_eth_port = T.ethernet_port(
            cls.device,
            T.RX_SLICE,
            T.RX_IFG + 1,
            cls.RX_SYS_PORT_GID + 1,
            cls.RX_SERDES_FIRST,
            cls.RX_SERDES_LAST)
        cls.create_l3_ac()
        cls.add_prefix()

        cls.create_lag()

    @classmethod
    def create_l3_ac(cls):
        cls.rx_l3_ac = T.l3_ac_port(cls.device, 3939, cls.rx_eth_port,
                                    cls.topology.vrf, T.RX_L3_AC_MAC, vid1=cls.RX_AC_PORT_VID1, vid2=0)
        cls.rx_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        cls.tx_l3_ac = T.l3_ac_port(cls.device, 3990, cls.tx_eth_port,
                                    cls.topology.vrf, T.TX_L3_AC_REG_MAC, vid1=cls.TX_AC_PORT_VID1, vid2=0)
        tag = sdk.la_vlan_tag_t()
        tag.tpid = 0x8100
        tag.tci.fields.pcp = 0
        tag.tci.fields.dei = 0
        tag.tci.fields.vid = cls.TX_AC_PORT_VID1
        cls.tx_l3_ac.hld_obj.set_egress_vlan_tag(tag, sdk.LA_VLAN_TAG_UNTAGGED)
        cls.tx_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)

    @classmethod
    def add_prefix(cls):
        prefix = cls.ip_impl.build_prefix(cls.DIP, length=16)
        nh_l3_ac = T.next_hop(cls.device, T.NH_L3_AC_REG_GID + 1, T.NH_L3_AC_REG_MAC, cls.tx_l3_ac)
        fec = T.fec(cls.device, nh_l3_ac)
        cls.ip_impl.add_route(cls.topology.vrf, prefix, fec, ip_routing_base.PRIVATE_DATA)

    @classmethod
    def create_lag(cls):
        mac_port_member_1 = T.mac_port(
            cls.device,
            SLICE,
            IFG + 1,
            FIRST_SERDES1,
            LAST_SERDES1)
        cls.sys_port_member_1 = T.system_port(cls.device, 100, mac_port_member_1)
        mac_port_member_2 = T.mac_port(
            cls.device,
            SLICE + 1,
            IFG + 1,
            FIRST_SERDES1,
            LAST_SERDES1)
        cls.sys_port_member_2 = T.system_port(cls.device, 101, mac_port_member_2)
        cls.spa_port = T.spa_port(cls.device, 123)

        cls.spa_port.add(cls.sys_port_member_1)
        cls.spa_port.add(cls.sys_port_member_2)

        cls.eth_port = T.sa_ethernet_port(cls.device, cls.spa_port)
        cls.rx_spa_l3_ac = T.l3_ac_port(
            cls.device,
            SPA_L3AC_GID,
            cls.eth_port,
            cls.topology.vrf,
            T.RX_L3_AC_MAC,
            vid1=cls.RX_AC_PORT_VID1,
            vid2=0)
        cls.rx_spa_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_single_to_single_tag_spa(self):

        # Being with accepting RX_AC_PORT_VID1
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, SLICE, IFG + 1, FIRST_SERDES1,
                          self.EXPECTED_OUTPUT_PACKET, T.RX_SLICE, T.RX_IFG + 1, self.RX_SERDES_FIRST)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, SLICE + 1, IFG + 1, FIRST_SERDES1,
                          self.EXPECTED_OUTPUT_PACKET, T.RX_SLICE, T.RX_IFG + 1, self.RX_SERDES_FIRST)

        # Change vlan to DUMMY_VID2
        self.rx_spa_l3_ac.hld_obj.set_service_mapping_vids(self.DUMMY_VID2, sdk.LA_VLAN_ID_INVALID)

        # verify DUMMY_VID2 is accepted
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_DOT1Q_NEW, SLICE, IFG + 1, FIRST_SERDES1,
                          self.EXPECTED_OUTPUT_PACKET, T.RX_SLICE, T.RX_IFG + 1, self.RX_SERDES_FIRST)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_DOT1Q_NEW, SLICE + 1, IFG + 1, FIRST_SERDES1,
                          self.EXPECTED_OUTPUT_PACKET, T.RX_SLICE, T.RX_IFG + 1, self.RX_SERDES_FIRST)

        # Revert back to RX_AC_PORT_VID1
        self.rx_spa_l3_ac.hld_obj.set_service_mapping_vids(self.RX_AC_PORT_VID1, sdk.LA_VLAN_ID_INVALID)

        # Verify RX_AC_PORT_VID1 is now accepted
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, SLICE, IFG + 1, FIRST_SERDES1,
                          self.EXPECTED_OUTPUT_PACKET, T.RX_SLICE, T.RX_IFG + 1, self.RX_SERDES_FIRST)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, SLICE + 1, IFG + 1, FIRST_SERDES1,
                          self.EXPECTED_OUTPUT_PACKET, T.RX_SLICE, T.RX_IFG + 1, self.RX_SERDES_FIRST)

        # Verify DUMMY_VID2 is usable by a new l3_ac
        self.rx_l3_ac_1 = T.l3_ac_port(self.device, 8991, self.eth_port,
                                       self.topology.vrf, T.RX_L3_AC_MAC, vid1=self.DUMMY_VID2, vid2=0)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_single_to_single_tag(self):

        # Being with accepting RX_AC_PORT_VID1
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, self.RX_SERDES_FIRST,
                          self.EXPECTED_OUTPUT_PACKET, T.RX_SLICE, T.RX_IFG + 1, self.RX_SERDES_FIRST)

        # Change vlan to DUMMY_VID2
        self.rx_l3_ac.hld_obj.set_service_mapping_vids(self.DUMMY_VID2, sdk.LA_VLAN_ID_INVALID)

        # verify DUMMY_VID2 is accepted
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_DOT1Q_NEW, T.RX_SLICE, T.RX_IFG, self.RX_SERDES_FIRST,
                          self.EXPECTED_OUTPUT_PACKET, T.RX_SLICE, T.RX_IFG + 1, self.RX_SERDES_FIRST)

        # Revert back to RX_AC_PORT_VID1
        self.rx_l3_ac.hld_obj.set_service_mapping_vids(self.RX_AC_PORT_VID1, sdk.LA_VLAN_ID_INVALID)

        # Verify RX_AC_PORT_VID1 is now accepted
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, self.RX_SERDES_FIRST,
                          self.EXPECTED_OUTPUT_PACKET, T.RX_SLICE, T.RX_IFG + 1, self.RX_SERDES_FIRST)

        # Verify DUMMY_VID2 is usable by a new l3_ac
        self.rx_l3_ac_1 = T.l3_ac_port(self.device, 8991, self.rx_eth_port,
                                       self.topology.vrf, T.RX_L3_AC_MAC, vid1=self.DUMMY_VID2, vid2=0)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_single_to_two_tag(self):

        # Being with accepting RX_AC_PORT_VID1
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, self.RX_SERDES_FIRST,
                          self.EXPECTED_OUTPUT_PACKET, T.RX_SLICE, T.RX_IFG + 1, self.RX_SERDES_FIRST)

        # Change vlan to DUMMY_VID2, RX_AC_PORT_VID1
        self.rx_l3_ac.hld_obj.set_service_mapping_vids(self.DUMMY_VID2, self.RX_AC_PORT_VID1)

        # verify DUMMY_VID2 is accepted
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_QINQ, T.RX_SLICE, T.RX_IFG, self.RX_SERDES_FIRST,
                          self.EXPECTED_OUTPUT_PACKET, T.RX_SLICE, T.RX_IFG + 1, self.RX_SERDES_FIRST)

        # Revert back to RX_AC_PORT_VID1
        self.rx_l3_ac.hld_obj.set_service_mapping_vids(self.RX_AC_PORT_VID1, sdk.LA_VLAN_ID_INVALID)

        # Verify RX_AC_PORT_VID1 is now accepted
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, self.RX_SERDES_FIRST,
                          self.EXPECTED_OUTPUT_PACKET, T.RX_SLICE, T.RX_IFG + 1, self.RX_SERDES_FIRST)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_single_to_two_tag_spa(self):

        # Being with accepting RX_AC_PORT_VID1
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, SLICE, IFG + 1, FIRST_SERDES1,
                          self.EXPECTED_OUTPUT_PACKET, T.RX_SLICE, T.RX_IFG + 1, self.RX_SERDES_FIRST)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, SLICE + 1, IFG + 1, FIRST_SERDES1,
                          self.EXPECTED_OUTPUT_PACKET, T.RX_SLICE, T.RX_IFG + 1, self.RX_SERDES_FIRST)

        # Change vlan to DUMMY_VID2, RX_AC_PORT_VID1
        self.rx_spa_l3_ac.hld_obj.set_service_mapping_vids(self.DUMMY_VID2, self.RX_AC_PORT_VID1)

        # verify DUMMY_VID2 is accepted
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_QINQ, SLICE, IFG + 1, FIRST_SERDES1,
                          self.EXPECTED_OUTPUT_PACKET, T.RX_SLICE, T.RX_IFG + 1, self.RX_SERDES_FIRST)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_QINQ, SLICE + 1, IFG + 1, FIRST_SERDES1,
                          self.EXPECTED_OUTPUT_PACKET, T.RX_SLICE, T.RX_IFG + 1, self.RX_SERDES_FIRST)

        # Revert back to RX_AC_PORT_VID1
        self.rx_spa_l3_ac.hld_obj.set_service_mapping_vids(self.RX_AC_PORT_VID1, sdk.LA_VLAN_ID_INVALID)

        # Verify RX_AC_PORT_VID1 is now accepted
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, SLICE, IFG + 1, FIRST_SERDES1,
                          self.EXPECTED_OUTPUT_PACKET, T.RX_SLICE, T.RX_IFG + 1, self.RX_SERDES_FIRST)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, SLICE + 1, IFG + 1, FIRST_SERDES1,
                          self.EXPECTED_OUTPUT_PACKET, T.RX_SLICE, T.RX_IFG + 1, self.RX_SERDES_FIRST)


if __name__ == '__main__':
    unittest.main()
