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

from packet_test_utils import *
from scapy.all import *
import unittest
import sim_utils
import topology as T
from sdk_test_case_base import *
from spa_port_base import *
try:
    import test_nsim_providercli as nsim
except BaseException:
    import test_packet_provider as nsim
import decor

# Helper class


class phy_port:
    pass


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_spa_port(spa_port_base):

    def setUp(self, create_spa_topology=True):
        super().setUp(create_spa_topology=False)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ac_port_creation_on_spa_delayed_system_port_add_and_forwarding(self):
        vid1 = self.VLAN
        vid2 = 0x0

        # Create RX ac port
        _mac_port = T.mac_port(self, self.device, self.IN_SLICE, self.IN_IFG, self.IN_SERDES_FIRST, self.IN_SERDES_LAST)
        _mac_port.activate()
        sys_port = T.system_port(self, self.device, self.SYS_PORT_GID_BASE, _mac_port)
        rx_eth_port = T.sa_ethernet_port(self, self.device, sys_port)
        ac_port_sp = self.create_ac_port_on_ethernet_port(rx_eth_port, self.AC_PORT_GID_BASE, vid1, vid2)

        # Create TX SPA
        spa_port = T.spa_port(self, self.device, 123)
        mac_port_member_1 = T.mac_port(
            self,
            self.device,
            self.s_tx[0].slice,
            self.s_tx[0].ifg,
            self.s_tx[0].first_serdes,
            self.s_tx[0].last_serdes)
        mac_port_member_1.activate()
        sys_port_member_1 = T.system_port(self, self.device, 10, mac_port_member_1)

        mac_port_member_2 = T.mac_port(
            self,
            self.device,
            self.s_tx[1].slice,
            self.s_tx[1].ifg,
            self.s_tx[1].first_serdes,
            self.s_tx[1].last_serdes)
        mac_port_member_2.activate()
        sys_port_member_2 = T.system_port(self, self.device, 11, mac_port_member_2)

        mac_port_member_3 = T.mac_port(
            self,
            self.device,
            self.s_tx[2].slice,
            self.s_tx[2].ifg,
            self.s_tx[2].first_serdes,
            self.s_tx[2].last_serdes)
        mac_port_member_3.activate()
        sys_port_member_3 = T.system_port(self, self.device, 12, mac_port_member_3)
        mac_port_member_4 = T.mac_port(
            self,
            self.device,
            self.s_tx[3].slice,
            self.s_tx[3].ifg,
            self.s_tx[3].first_serdes,
            self.s_tx[3].last_serdes)
        mac_port_member_4.activate()
        sys_port_member_4 = T.system_port(self, self.device, 14, mac_port_member_4)
        # add system ports to SPA
        spa_port.add(sys_port_member_1)
        spa_port.add(sys_port_member_2)

        # Create TX Ethernet port over the SPA
        tx_eth_port = T.sa_ethernet_port(self, self.device, spa_port)

        # Create TX ac port over the SPA eth_port
        ac_port_spa = self.create_ac_port_on_ethernet_port(tx_eth_port, 143, vid1, vid2)

        # Create Switch
        sw1 = T.switch(self, self.device, 100)

        # Attach RX and TX ac ports to switch
        ac_port_sp.hld_obj.attach_to_switch(sw1.hld_obj)
        ac_port_spa.hld_obj.attach_to_switch(sw1.hld_obj)

        # Add 'cafecafecafe' to the MAC table, going to SPA ac port
        dest_mac = sdk.la_mac_addr_t()
        dest_mac.flat = 0xcafecafecafe
        sw1.hld_obj.set_mac_entry(dest_mac, ac_port_spa.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)

        # Inject packets SP-AC -> SPA-AC
        self.run_and_compare_spa(
            spa_port,
            sdk.LA_LB_VECTOR_IPV4_NON_TCP_UDP,
            self.in_packet_a,
            self.IN_SLICE,
            self.IN_IFG,
            self.IN_SERDES_FIRST,
            self.out_packet_a)
        self.run_and_compare_spa(
            spa_port,
            sdk.LA_LB_VECTOR_IPV4_NON_TCP_UDP,
            self.in_packet_b,
            self.IN_SLICE,
            self.IN_IFG,
            self.IN_SERDES_FIRST,
            self.out_packet_b)
        self.run_and_compare_spa(
            spa_port,
            sdk.LA_LB_VECTOR_IPV6_TCP_UDP,
            self.in_packet_d,
            self.IN_SLICE,
            self.IN_IFG,
            self.IN_SERDES_FIRST,
            self.out_packet_d)

        # add system ports to SPA
        spa_port.add(sys_port_member_3)
        spa_port.add(sys_port_member_4)

        # Add a MAC on normal AC to test Ingress SPA
        dest_mac.flat = 0xcafecafecaff
        sw1.hld_obj.set_mac_entry(dest_mac, ac_port_sp.hld_obj, sdk.LA_MAC_AGING_TIME_NEVER)
        # Inject packets SPA-AC -> SP-AC
        self.inject_and_verify_packet_ingress(self.in_packet_c, self.out_packet_c, 1)

        # Inject packets on new member SPA-AC -> SP-AC
        self.inject_and_verify_packet_ingress(self.in_packet_c, self.out_packet_c, 2)
        self.inject_and_verify_packet_ingress(self.in_packet_c, self.out_packet_c, 3)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ethernet_port_creation_delayed_system_port_add(self):
        sys_port_member_0 = self.create_sys_port_from_phy_port(0, self.SYS_PORT_GID_BASE)
        sys_port_member_1 = self.create_sys_port_from_phy_port(1, self.SYS_PORT_GID_BASE + 1)

        spa_port = T.spa_port(self, self.device, 123)

        # create Ethernet port over the SPA
        eth_port = T.sa_ethernet_port(self, self.device, spa_port)

        # add system ports to SPA
        spa_port.add(sys_port_member_0)
        spa_port.add(sys_port_member_1)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ethernet_port_creation(self):
        sys_port_member_0 = self.create_sys_port_from_phy_port(0, 100)
        sys_port_member_1 = self.create_sys_port_from_phy_port(1, 101)

        spa_port = T.spa_port(self, self.device, 123)

        spa_port.add(sys_port_member_0)
        spa_port.add(sys_port_member_1)

        eth_port = T.sa_ethernet_port(self, self.device, spa_port)

    @unittest.skipIf(decor.is_asic5(), "Test is not applicable to AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_mac_port_serdes_overlap(self):
        FIRST_SLICE = 0
        SECOND_SLICE = 1

        FIRST_SERDES = 0
        SECOND_SERDES = 1
        FIRST_SERDES_2 = 1
        SECOND_SERDES_2 = 1

        mac_port = T.mac_port(self, self.device, FIRST_SLICE, self.IN_IFG, FIRST_SERDES, SECOND_SERDES)

        try:
            self.device.create_mac_port(FIRST_SLICE, self.IN_IFG, FIRST_SERDES_2, SECOND_SERDES_2,
                                        sdk.la_mac_port.port_speed_e_E_25G,
                                        sdk.la_mac_port.fc_mode_e_NONE,
                                        sdk.la_mac_port.fec_mode_e_NONE)
            self.assertFail()
        except sdk.BaseException:
            pass

        mac_port2 = self.device.create_mac_port(SECOND_SLICE, self.IN_IFG, FIRST_SERDES_2, SECOND_SERDES_2,
                                                sdk.la_mac_port.port_speed_e_E_25G,
                                                sdk.la_mac_port.fc_mode_e_NONE,
                                                sdk.la_mac_port.fec_mode_e_NONE)
        self.assertIsNotNone(mac_port2)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_spa_port_creation_and_destruction(self):
        sys_port_member_0 = self.create_sys_port_from_phy_port(0, 100)
        sys_port_member_1 = self.create_sys_port_from_phy_port(1, 101)

        spa_port = T.spa_port(self, self.device, 123)

        spa_port.add(sys_port_member_0)
        spa_port.add(sys_port_member_1)

        spa_port.destroy()  # Verify that an empty SPA can be destroyed

        # Re-create the same SPA, add it to an eth_port and verify is not destroyed as long as eth_port is depends on it
        spa_port = T.spa_port(self, self.device, 123)

        spa_port.add(sys_port_member_0)
        spa_port.add(sys_port_member_1)

        eth_port = T.sa_ethernet_port(self, self.device, spa_port)

        try:
            self.device.destroy(spa_port.hld_obj)
            self.assertFail()
        except sdk.BaseException:
            pass

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_spa_port_creation(self):
        sys_port_member_0 = self.create_sys_port_from_phy_port(0, 100)
        sys_port_member_1 = self.create_sys_port_from_phy_port(1, 101)

        spa_port = T.spa_port(self, self.device, 123)

        spa_port.add(sys_port_member_0)
        spa_port.add(sys_port_member_1)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_spa_port_getters(self):
        # Re-create the same SPA, add it to an eth_port and verify is not destroyed as long as eth_port is depends on it
        spa_port = self.create_spa_port_with_two_system_ports()

        # Check set/get lb_mode
        for lb_mode in [sdk.la_lb_mode_e_CONSISTENT, sdk.la_lb_mode_e_DYNAMIC]:
            expected = lb_mode
            spa_port.set_lb_mode(expected)
            res = spa_port.get_lb_mode()
            self.assertEqual(expected, res)

        # Check get_member
        res_sys_port = spa_port.hld_obj.get_member(0)
        self.assertEqual(res_sys_port.this, self.m_sys_port_member_0.hld_obj.this)

        try:
            spa_port.hld_obj.get_member(5)
            self.assertFail()
        except sdk.BaseException:
            pass

        # Check get_members
        res_sys_ports = spa_port.hld_obj.get_members()
        self.assertEqual(res_sys_ports[0].this, self.m_sys_port_member_0.hld_obj.this)
        self.assertEqual(res_sys_ports[1].this, self.m_sys_port_member_1.hld_obj.this)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_two_system_one_mac(self):
        SYSTEM_PORT_GID_1 = 20
        SYSTEM_PORT_GID_2 = 25

        mac_port = T.mac_port(self, self.device, self.IN_SLICE, self.IN_IFG, self.IN_SERDES_FIRST, self.IN_SERDES_LAST)
        sys_port = T.system_port(self, self.device, SYSTEM_PORT_GID_1, mac_port)

        sysport_creation_failed = False
        sys_port2 = None
        try:
            sys_port2 = T.system_port(self, self.device, SYSTEM_PORT_GID_1, mac_port)
        except sdk.BaseException:
            sysport_creation_failed = True

        self.assertTrue(sysport_creation_failed)
        self.assertEqual(sys_port2, None)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_switch_mac_forwarding_to_spa_port_to_sp1(self):
        self.create_topology()

        self.run_and_compare_spa(
            self.m_spa_port,
            sdk.LA_LB_VECTOR_IPV4_NON_TCP_UDP,
            self.in_packet_a,
            self.IN_SLICE,
            self.IN_IFG,
            self.IN_SERDES_FIRST,
            self.out_packet_a)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_switch_mac_forwarding_to_spa_port_to_sp2(self):
        self.create_topology()

        self.run_and_compare_spa(
            self.m_spa_port,
            sdk.LA_LB_VECTOR_IPV4_NON_TCP_UDP,
            self.in_packet_b,
            self.IN_SLICE,
            self.IN_IFG,
            self.IN_SERDES_FIRST,
            self.out_packet_b)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_spa_member_remove_all(self):
        self.create_topology()

        self.m_spa_port.remove(self.m_sys_port_member_0)
        self.m_spa_port.remove(self.m_sys_port_member_1)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_spa_member_remove_and_mac_forward(self):
        self.create_topology()

        self.m_spa_port.remove(self.m_sys_port_member_0)
        self.m_spa_port.add(self.m_sys_port_member_0)

        self.run_and_compare_spa(
            self.m_spa_port,
            sdk.LA_LB_VECTOR_IPV4_NON_TCP_UDP,
            self.in_packet_a,
            self.IN_SLICE,
            self.IN_IFG,
            self.IN_SERDES_FIRST,
            self.out_packet_a)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_spa_member_remove_readd_and_mac_forward(self):
        self.create_topology()

        self.m_spa_port.remove(self.m_sys_port_member_0)
        self.m_spa_port.add(self.m_sys_port_member_0)

        # The first member was erased and readded
        self.run_and_compare_spa(
            self.m_spa_port,
            sdk.LA_LB_VECTOR_IPV4_NON_TCP_UDP,
            self.in_packet_b,
            self.IN_SLICE,
            self.IN_IFG,
            self.IN_SERDES_FIRST,
            self.out_packet_b)

    # spa port events
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_initial_traffic(self):
        self.create_topology()

        # 2 members are added and enabled for transmit
        self.run_and_compare_spa(
            self.m_spa_port,
            sdk.LA_LB_VECTOR_IPV4_NON_TCP_UDP,
            self.in_packet_a,
            self.IN_SLICE,
            self.IN_IFG,
            self.IN_SERDES_FIRST,
            self.out_packet_a)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_member_disable_enable(self):
        self.create_topology()

        # 2 members are added and enabled for transmit
        # disable member 0. Packet should use 1.
        self.m_spa_port.hld_obj.set_member_transmit_enabled(self.m_sys_port_member_0.hld_obj, False)
        self.inject_and_verify_packet(self.in_packet_a, self.out_packet_a, 1)

        # disable member 1. Enable member 0. Packet should use 0.
        self.m_spa_port.hld_obj.set_member_transmit_enabled(self.m_sys_port_member_1.hld_obj, False)
        self.m_spa_port.hld_obj.set_member_transmit_enabled(self.m_sys_port_member_0.hld_obj, True)
        self.inject_and_verify_packet(self.in_packet_a, self.out_packet_a, 0)

        # disable member 0. Enable member 1. Packet should use 1.
        self.m_spa_port.hld_obj.set_member_transmit_enabled(self.m_sys_port_member_0.hld_obj, False)
        self.m_spa_port.hld_obj.set_member_transmit_enabled(self.m_sys_port_member_1.hld_obj, True)
        self.inject_and_verify_packet(self.in_packet_a, self.out_packet_a, 1)

        # now enable member 0 (both ports are transmit enabled)
        self.m_spa_port.hld_obj.set_member_transmit_enabled(self.m_sys_port_member_0.hld_obj, True)
        self.run_and_compare_spa(
            self.m_spa_port,
            sdk.LA_LB_VECTOR_IPV4_NON_TCP_UDP,
            self.in_packet_a,
            self.IN_SLICE,
            self.IN_IFG,
            self.IN_SERDES_FIRST,
            self.out_packet_a)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_duplicate_enable(self):
        self.create_topology()

        # enable member 0 again. Should pass without error. packet to use destination based on lb.
        self.m_spa_port.hld_obj.set_member_transmit_enabled(self.m_sys_port_member_0.hld_obj, True)
        self.run_and_compare_spa(
            self.m_spa_port,
            sdk.LA_LB_VECTOR_IPV4_NON_TCP_UDP,
            self.in_packet_a,
            self.IN_SLICE,
            self.IN_IFG,
            self.IN_SERDES_FIRST,
            self.out_packet_a)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_duplicate_disable(self):
        self.create_topology()

        # disable member 1 twice. Should pass without error. packet to use member 0.
        self.m_spa_port.hld_obj.set_member_transmit_enabled(self.m_sys_port_member_1.hld_obj, False)
        self.m_spa_port.hld_obj.set_member_transmit_enabled(self.m_sys_port_member_1.hld_obj, False)
        self.inject_and_verify_packet(self.in_packet_a, self.out_packet_a, 0)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_non_member_enable(self):
        self.create_topology()

        # remove member 1 and try enable it
        self.m_spa_port.remove(self.m_sys_port_member_1)
        with self.assertRaises(sdk.NotFoundException):
            self.m_spa_port.hld_obj.set_member_transmit_enabled(self.m_sys_port_member_1.hld_obj, True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_non_member_disable(self):
        self.create_topology()

        # remove member 1 and try disable it
        self.m_spa_port.remove(self.m_sys_port_member_1)
        with self.assertRaises(sdk.NotFoundException):
            self.m_spa_port.hld_obj.set_member_transmit_enabled(self.m_sys_port_member_1.hld_obj, False)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_active_member_removal(self):
        self.create_topology()

        with self.assertRaises(sdk.BusyException):
            self.m_spa_port.hld_obj.remove(self.m_sys_port_member_0.hld_obj)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_remove_add_sequence(self):
        self.create_topology()

        # remove member 0. Packet should use member 1
        self.m_spa_port.remove(self.m_sys_port_member_0)
        self.inject_and_verify_packet(self.in_packet_a, self.out_packet_a, 1)

        # add member back. packet should use destination based on lb
        self.m_spa_port.add(self.m_sys_port_member_0)
        self.run_and_compare_spa(
            self.m_spa_port,
            sdk.LA_LB_VECTOR_IPV4_NON_TCP_UDP,
            self.in_packet_a,
            self.IN_SLICE,
            self.IN_IFG,
            self.IN_SERDES_FIRST,
            self.out_packet_a)

        # Now disable member 1. packet should use member 0
        self.m_spa_port.hld_obj.set_member_transmit_enabled(self.m_sys_port_member_1.hld_obj, False)
        self.inject_and_verify_packet(self.in_packet_a, self.out_packet_a, 0)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_duplicate_add(self):
        self.create_topology()

        with self.assertRaises(sdk.BusyException):
            self.m_spa_port.hld_obj.add(self.m_sys_port_member_0.hld_obj)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_duplicate_remove(self):
        self.create_topology()

        # try remove member twice
        self.m_spa_port.remove(self.m_sys_port_member_0)
        with self.assertRaises(sdk.NotFoundException):
            self.m_spa_port.hld_obj.remove(self.m_sys_port_member_0.hld_obj)

    @unittest.skipIf(decor.is_asic5(), "Test fails on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_dspa_table(self):
        if T.is_matilda_model(self.device):
            self.skipTest("This device does not support serdes speed >25. Thus, this test is irrelevant.")
            return
        sys_port_member_0 = self.create_sys_port_from_phy_port(0, 100)
        sys_port_member_1 = self.create_sys_port_from_phy_port(1, 101)

        spa_port = T.spa_port(self, self.device, 123)

        spa_port.add(sys_port_member_0)
        spa_port.add(sys_port_member_1)

        members = spa_port.hld_obj.get_dspa_table_members()
        self.assertEqual(len(members), 2)

        # Disable a member and check the size
        spa_port.hld_obj.set_member_transmit_enabled(sys_port_member_0.hld_obj, False)
        members = spa_port.hld_obj.get_dspa_table_members()
        self.assertEqual(len(members), 1)

        # re-enable the member and check the size
        spa_port.hld_obj.set_member_transmit_enabled(sys_port_member_0.hld_obj, True)
        members = spa_port.hld_obj.get_dspa_table_members()
        self.assertEqual(len(members), 2)

        macport = sys_port_member_0.hld_obj.get_underlying_port()
        fc_mode = macport.get_fc_mode(sdk.la_mac_port.fc_direction_e_RX)
        fec_mode = macport.get_fec_mode()
        speed = macport.get_serdes_speed()
        self.assertEqual(speed, sdk.la_mac_port.port_speed_e_E_25G)

        # change port speed from 50G to 100G
        macport.reconfigure(2, sdk.la_mac_port.port_speed_e_E_100G, fc_mode, fc_mode, fec_mode)

        # now dspa should have 0, 0, 1 size 3
        members = spa_port.hld_obj.get_dspa_table_members()
        self.assertEqual(len(members), 3)

        # change port speed back to 50G. Each serdes gets 25G
        macport.reconfigure(2, sdk.la_mac_port.port_speed_e_E_50G, fc_mode, fc_mode, fec_mode)

        # dspa should fall back to 2 entries
        members = spa_port.hld_obj.get_dspa_table_members()
        self.assertEqual(len(members), 2)


if __name__ == '__main__':
    unittest.main()
