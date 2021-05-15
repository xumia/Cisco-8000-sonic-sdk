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
import unittest
import decor
import packet_test_utils as U
import scapy.all as S
import topology as T
from ip_routing_base import *
from ipv4_l3_ac_routing_base import *

BASE_VOQ_ID = 350
SET_SIZE = 2
BASE_VSC = 200

SPA_L3AC_GID = 3399
SLICE = T.get_device_slice(3)
IFG = 0
FIRST_SERDES1 = T.get_device_first_serdes(4)
LAST_SERDES1 = T.get_device_last_serdes(5)

SLICE2 = T.get_device_slice(SLICE + 1)
FIRST_SERDES2 = T.get_device_next_first_serdes(FIRST_SERDES1)
LAST_SERDES2 = T.get_device_next_last_serdes(LAST_SERDES1)


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class ipv4_routing_subinterfac_qos(ipv4_l3_ac_routing_base):
    voq_set = []
    l3_ac = []

    def create_voq_set(self):
        is_success, base_voq, base_vsc_vec = T.topology.allocate_voq_set(
            self.device, self.device.get_id(), T.TX_SLICE_REG, T.TX_IFG_REG, SET_SIZE)
        self.assertTrue(is_success)
        self.voq_set = self.device.create_voq_set(
            base_voq,
            SET_SIZE,
            base_vsc_vec,
            self.device.get_id(),
            T.TX_SLICE_REG,
            T.TX_IFG_REG)
        for voq in range(SET_SIZE):
            self.voq_set.set_cgm_profile(voq, self.topology.uc_voq_cgm_profile_def)

    def create_spa_voq_set(self):
        # MATILDA_SAVE
        global SLICE, SLICE1
        if (SLICE not in self.device.get_used_slices()):
            SLICE = 1
        SLICE1 = SLICE + 1
        if (SLICE1 not in self.device.get_used_slices()):
            SLICE1 = SLICE - 1

        is_success, base_voq, base_vsc_vec = T.topology.allocate_voq_set(self.device, self.device.get_id(), SLICE, IFG, SET_SIZE)
        self.assertTrue(is_success)
        self.voq_set_sp1 = self.device.create_voq_set(
            base_voq,
            SET_SIZE,
            base_vsc_vec,
            self.device.get_id(),
            SLICE,
            IFG)
        for voq in range(SET_SIZE):
            self.voq_set_sp1.set_cgm_profile(voq, self.topology.uc_voq_cgm_profile_def)

        is_success, base_voq, base_vsc_vec = T.topology.allocate_voq_set(
            self.device, self.device.get_id(), SLICE1, IFG, SET_SIZE)
        self.assertTrue(is_success)
        self.voq_set_sp2 = self.device.create_voq_set(
            base_voq,
            SET_SIZE,
            base_vsc_vec,
            self.device.get_id(),
            SLICE1,
            IFG)
        for voq in range(SET_SIZE):
            self.voq_set_sp2.set_cgm_profile(voq, self.topology.uc_voq_cgm_profile_def)

    def create_l3_ac(self):
        topology_tc = self.topology.tc_profile_def
        self.l3_ac = T.l3_ac_port(self, self.device, 3939, self.topology.tx_l3_ac_eth_port_reg,
                                  self.topology.vrf, T.TX_L3_AC_REG_MAC, vid1=self.OUTPUT_VID, vid2=0)
        self.l3_ac.hld_obj.set_tc_profile(topology_tc.hld_obj)

    def create_lag(self):
        # MATILDA_SAVE
        global SLICE, SLICE1
        if (SLICE not in self.device.get_used_slices()):
            SLICE = 1
        SLICE1 = SLICE + 1
        if (SLICE1 not in self.device.get_used_slices()):
            SLICE1 = SLICE - 1

        SLICE = T.get_device_slice(SLICE)
        SLICE1 = T.get_device_slice(SLICE1)
        mac_port_member_1 = T.mac_port(
            self,
            self.device,
            SLICE,
            IFG,
            FIRST_SERDES1,
            LAST_SERDES1)
        self.sys_port_member_1 = T.system_port(self, self.device, 100, mac_port_member_1)
        mac_port_member_2 = T.mac_port(
            self,
            self.device,
            SLICE1,
            IFG,
            FIRST_SERDES2,
            LAST_SERDES2)
        self.sys_port_member_2 = T.system_port(self, self.device, 101, mac_port_member_2)
        self.spa_port = T.spa_port(self, self.device, 123)

        self.spa_port.add(self.sys_port_member_1)
        self.spa_port.add(self.sys_port_member_2)

        eth_port = T.sa_ethernet_port(self, self.device, self.spa_port)
        topology_tc = self.topology.tc_profile_def
        self.spa_l3_ac = T.l3_ac_port(
            self,
            self.device,
            SPA_L3AC_GID,
            eth_port,
            self.topology.vrf,
            T.TX_L3_AC_REG_MAC,
            vid1=self.OUTPUT_VID,
            vid2=0)
        self.spa_l3_ac.hld_obj.set_tc_profile(topology_tc.hld_obj)

    def add_prefix(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        nh_l3_ac = T.next_hop(self, self.device, T.NH_L3_AC_REG_GID + 1, T.NH_L3_AC_REG_MAC, self.l3_ac)
        fec = T.fec(self, self.device, nh_l3_ac)
        self.ip_impl.add_route(self.topology.vrf, prefix, fec, ip_routing_base.PRIVATE_DATA)

    def add_spa_prefix(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        nh_l3_ac = T.next_hop(self, self.device, T.NH_L3_AC_REG_GID + 1, T.NH_L3_AC_REG_MAC, self.spa_l3_ac)
        fec = T.fec(self, self.device, nh_l3_ac)
        self.ip_impl.add_route(self.topology.vrf, prefix, fec, ip_routing_base.PRIVATE_DATA)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_reject_no_tc_profile(self):
        self.create_voq_set()
        system_port = self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj
        with self.assertRaises(sdk.BaseException) as cm:
            self.topology.tx_l3_ac_reg.hld_obj.set_system_port_voq_set(system_port, self.voq_set)
            STATUS = cm.exception
            self.assertEqual(STATUS.args[0], sdk.la_status_e_E_NOTINITIALIZED)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_reject_on_different_sp(self):
        self.create_voq_set()
        self.create_l3_ac()

        system_port = self.topology.rx_eth_port.sys_port.hld_obj
        with self.assertRaises(sdk.BaseException) as cm:
            self.l3_ac.hld_obj.set_system_port_voq_set(system_port, self.voq_set)
            STATUS = cm.exception
            self.assertEqual(STATUS.args[0], sdk.la_status_e_E_INVAL)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet applicable to AR - only one slice")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_reject_voq_systemport_mismatch(self):
        self.create_voq_set()
        self.create_lag()

        with self.assertRaises(sdk.BaseException) as cm:
            self.spa_l3_ac.hld_obj.set_system_port_voq_set(self.sys_port_member_1.hld_obj, self.voq_set)
            STATUS = cm.exception
            self.assertEqual(STATUS.args[0], sdk.la_status_e_E_INVAL)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_subif_qos_update_voq_set(self):
        self.create_voq_set()
        self.create_l3_ac()
        system_port = self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj

        # create new voq set
        is_success, base_voq, base_vsc_vec = T.topology.allocate_voq_set(
            self.device, self.device.get_id(), T.TX_SLICE_REG, T.TX_IFG_REG, SET_SIZE)
        self.assertTrue(is_success)
        voq_set = self.device.create_voq_set(base_voq,
                                             SET_SIZE,
                                             base_vsc_vec,
                                             self.device.get_id(),
                                             T.TX_SLICE_REG,
                                             T.TX_IFG_REG)
        # Attach voq set
        self.l3_ac.hld_obj.set_system_port_voq_set(system_port, voq_set)

        # overwrite existing voq set
        self.l3_ac.hld_obj.set_system_port_voq_set(system_port, self.voq_set)

        # Make sure old voq is free
        voq_set.set_state(sdk.la_voq_set.state_e_DROPPING)
        self.device.destroy(voq_set)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_subif_qos_existing_prefix(self):
        self.create_voq_set()
        self.create_l3_ac()
        self.add_prefix()

        # Test packet before queuing
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        # add queuing on l3ac with NH already created
        system_port = self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj
        self.l3_ac.hld_obj.set_system_port_voq_set(system_port, self.voq_set)

        # Test packet after queuing
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.l3_ac.hld_obj.clear_system_port_voq_set(system_port)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_subif_qos_new_prefix(self):
        self.create_voq_set()
        self.create_l3_ac()

        system_port = self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj
        self.l3_ac.hld_obj.set_system_port_voq_set(system_port, self.voq_set)

        # add prefix on l3ac with qos
        self.add_prefix()
        # Test packet
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.l3_ac.hld_obj.clear_system_port_voq_set(system_port)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

    def run_and_compare_spa(self, spa_port, input_packet, input_slice, input_ifg, input_serdes, out_packet):
        lb_vec_entry_list = []

        lb_vec = sdk.la_lb_vector_t()
        dip = T.ipv4_addr(input_packet[S.IP].dst)
        sip = T.ipv4_addr(input_packet[S.IP].src)
        lb_vec.type = sdk.LA_LB_VECTOR_IPV4_NON_TCP_UDP
        lb_vec.ipv4.sip = sip.hld_obj.s_addr
        lb_vec.ipv4.dip = dip.hld_obj.s_addr
        lb_vec.ipv4.protocol = input_packet[S.IP].proto

        lb_vec_entry_list.append(lb_vec)

        out_dest_chain = self.device.get_forwarding_load_balance_chain(spa_port.hld_obj, lb_vec_entry_list)

        self.assertEqual(out_dest_chain[-1].type(), sdk.la_object.object_type_e_SYSTEM_PORT)

        out_dsp = out_dest_chain[-1].downcast()
        U.run_and_compare(self, self.device,
                          input_packet, input_slice, input_ifg, input_serdes,
                          out_packet, out_dsp.get_slice(), out_dsp.get_ifg(), out_dsp.get_base_serdes())

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    def test_lag_qos_existing_prefix(self):
        self.create_lag()
        self.create_spa_voq_set()
        self.add_spa_prefix()
        # Test packet
        self.run_and_compare_spa(self.spa_port,
                                 self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                 self.EXPECTED_OUTPUT_PACKET)

        self.spa_l3_ac.hld_obj.set_system_port_voq_set(self.sys_port_member_1.hld_obj, self.voq_set_sp1)
        self.spa_l3_ac.hld_obj.set_system_port_voq_set(self.sys_port_member_2.hld_obj, self.voq_set_sp2)

        # Test packet
        self.run_and_compare_spa(self.spa_port,
                                 self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                 self.EXPECTED_OUTPUT_PACKET)

        self.spa_l3_ac.hld_obj.clear_system_port_voq_set(self.sys_port_member_1.hld_obj)
        self.spa_l3_ac.hld_obj.clear_system_port_voq_set(self.sys_port_member_2.hld_obj)
        self.run_and_compare_spa(self.spa_port,
                                 self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                 self.EXPECTED_OUTPUT_PACKET)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    def test_lag_qos_new_prefix(self):
        self.create_lag()
        self.create_spa_voq_set()
        self.spa_l3_ac.hld_obj.set_system_port_voq_set(self.sys_port_member_1.hld_obj, self.voq_set_sp1)
        self.spa_l3_ac.hld_obj.set_system_port_voq_set(self.sys_port_member_2.hld_obj, self.voq_set_sp2)
        self.add_spa_prefix()
        # Test packet
        self.run_and_compare_spa(self.spa_port,
                                 self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                 self.EXPECTED_OUTPUT_PACKET)

        self.spa_l3_ac.hld_obj.clear_system_port_voq_set(self.sys_port_member_1.hld_obj)
        self.spa_l3_ac.hld_obj.clear_system_port_voq_set(self.sys_port_member_2.hld_obj)
        self.run_and_compare_spa(self.spa_port,
                                 self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                                 self.EXPECTED_OUTPUT_PACKET)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_subif_qos_destroy_l3_ac_with_qos(self):
        self.create_voq_set()
        self.create_l3_ac()
        system_port = self.topology.tx_l3_ac_eth_port_reg.sys_port.hld_obj
        self.l3_ac.hld_obj.set_system_port_voq_set(system_port, self.voq_set)

        # destroy l3_ac
        self.device.destroy(self.l3_ac.hld_obj)


if __name__ == '__main__':
    unittest.main()
