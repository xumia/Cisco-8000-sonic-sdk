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

import sys
import unittest
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import topology as T
from sdk_test_case_base import *
import ip_test_base
from copy import deepcopy
from packet_test_utils import *
import mtu.mtu_test_utils as MTU
from trap_counter_utils import *
import smart_slices_choise as ssch

NH_MAC_MODIFIED = T.mac_addr('00:01:02:03:04:05')
PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"
HOST_MAC_ADDR = "fe:dc:ba:98:76:54"
PUNT_VLAN = 0xA13
INJECT_VLAN = 0x1

SYS_PORT_GID_BASE = 23
IN_SP_GID = SYS_PORT_GID_BASE
OUT_SP_GID = SYS_PORT_GID_BASE + 1

VID1_2 = 0x44
VID2_2 = 0x55
SERDES = T.get_device_first_serdes(T.LAST_SERDES_L3 + 2)
SYS_PORT_GID = 0x28
AC_PORT_GID = 0x871
PORT_MAC_ADDR = T.mac_addr('00:38:39:3a:3b:3c')
NEW_PORT_MAC = T.mac_addr('00:03:03:03:03:03')
NEW_TX_PORT_MAC = T.mac_addr('00:04:04:04:04:04')

RX_AC_PORT_VID1 = 0x987
RX_AC_PORT_VID2 = 0x654

RX_AC_PORT_VID1_2 = 0x986
DUMMY_VID2 = 1

MIRROR_CMD_GID = 9
MIRROR_GID_INGRESS_OFFSET = 32
MIRROR_GID_EGRESS_OFFSET = 0
MIRROR_CMD_INGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_INGRESS_OFFSET
MIRROR_CMD_EGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_EGRESS_OFFSET
MIRROR_VLAN = 0xA12
PUNT_SLICE = T.get_device_slice(2)  # must be even numbered slice
PUNT_IFG = 0
PUNT_PIF_FIRST = T.get_device_punt_inject_first_serdes(8)
PUNT_PIF_LAST = PUNT_PIF_FIRST
PUNT_SP_GID = SYS_PORT_GID_BASE + 2 + 1

MAC_PORT_FIRST_SERDES = T.get_device_first_serdes(6)
MAC_PORT_LAST_SERDES = T.get_device_last_serdes(7)


class ip_routing_base(sdk_test_case_base):

    INJECT_SLICE = T.get_device_slice(3)
    INJECT_IFG = T.get_device_ifg(1)
    INJECT_PIF_FIRST = T.get_device_next_first_serdes(8)
    INJECT_SP_GID = SYS_PORT_GID_BASE + 2
    INJECT_SP_GID2 = SYS_PORT_GID_BASE + 3

    PRIVATE_DATA = 0x1234567890abcdef
    PRIVATE_DATA_DEFAULT = 0xfedcba9876543210
    CLASS_ID = 0xaf
    TTL = 128
    SA = T.mac_addr('be:ef:5d:35:7a:35')
    OUTPUT_VID = 0xac
    OUTPUT_VID1 = 0xad
    OUTPUT_VID2 = 0xae

    def setUp(self):
        super().setUp()
        ssch.rechoose_odd_inject_slice(self, self.device)

        self.l3_port_impl = self.l3_port_impl_class(self.topology)
        self.add_default_route()

    def add_default_route(self):
        prefix = self.ip_impl.get_default_prefix()
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.def_nh, ip_routing_base.PRIVATE_DATA_DEFAULT)
        self.has_default_route = True

    def destroy_default_route(self):
        if self.has_default_route:
            prefix = self.ip_impl.get_default_prefix()
            self.ip_impl.delete_route(self.topology.vrf, prefix)
            self.has_default_route = False

    def _try_clear_trap(self, trap):
        try:
            self.device.clear_trap_configuration(trap)
        except sdk.BaseException as STATUS:
            if (STATUS.args[0] != sdk.la_status_e_E_NOTFOUND):
                raise STATUS

    def _try_set_snoop(self, snoop, priority, mirror_cmd):
        try:
            self.device.set_snoop_configuration(snoop, priority, False, False, mirror_cmd)
        except sdk.BaseException as STATUS:
            if (STATUS.args[0] != sdk.la_status_e_E_NOTFOUND):
                raise STATUS

    def setup_ingress_egress_counters(self):
        # ingress L3 is l3_port_impl.rx_port
        self.l3_ingress_counter = self.device.create_counter(1)
        self.l3_port_impl.rx_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.l3_ingress_counter)

        # egress L3 is l3_port_impl.tx_port
        self.l3_egress_counter = self.device.create_counter(1)
        self.l3_port_impl.tx_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.l3_egress_counter)

        # ingress L2 is topology.rx_l2_ac_port
        self.l2_ingress_counter = self.device.create_counter(1)
        self.topology.rx_l2_ac_port.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_PORT, self.l2_ingress_counter)

        # egress L2 is topology.tx_l2_ac_port_reg
        self.l2_egress_counter = self.device.create_counter(1)
        self.topology.tx_l2_ac_port_reg.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.l2_egress_counter)

    def _test_add_host(self, disable_rx=False, disable_tx=False):
        subnet = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_subnet(self.l3_port_impl.tx_port, subnet)
        self.ip_impl.add_host(self.l3_port_impl.tx_port, self.DIP, self.l3_port_impl.reg_nh.mac_addr)
        self.setup_ingress_egress_counters()

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if(self.l3_port_impl.is_svi):
            packet_count, byte_count = self.l2_ingress_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            packet_count, byte_count = self.l2_egress_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET, byte_count)

        packet_count, byte_count = self.l3_ingress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.l3_egress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET, byte_count)

        if(self.l3_port_impl.is_svi != True):
            if(disable_rx):
                self.l3_port_impl.rx_port.hld_obj.disable()
                U.run_and_drop(self, self.device,
                               self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

            if(disable_tx):
                self.l3_port_impl.tx_port.hld_obj.disable()
                U.run_and_drop(self, self.device,
                               self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        self.ip_impl.delete_host(self.l3_port_impl.tx_port, self.DIP)
        self.ip_impl.delete_subnet(self.l3_port_impl.tx_port, subnet)

    def _test_add_host_then_subnet(self):
        subnet = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_host(self.l3_port_impl.tx_port, self.DIP, self.l3_port_impl.reg_nh.mac_addr)
        self.ip_impl.add_subnet(self.l3_port_impl.tx_port, subnet)
        self.setup_ingress_egress_counters()

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if(self.l3_port_impl.is_svi):
            packet_count, byte_count = self.l2_ingress_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            packet_count, byte_count = self.l2_egress_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET, byte_count)

        packet_count, byte_count = self.l3_ingress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.l3_egress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET, byte_count)

        self.ip_impl.delete_host(self.l3_port_impl.tx_port, self.DIP)
        self.ip_impl.delete_subnet(self.l3_port_impl.tx_port, subnet)

    def _test_add_host_then_subnet_then_delete(self):
        subnet = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_subnet(self.l3_port_impl.tx_port, subnet)
        self.ip_impl.add_host(self.l3_port_impl.tx_port, self.DIP, self.l3_port_impl.reg_nh.mac_addr)
        self.ip_impl.delete_subnet(self.l3_port_impl.tx_port, subnet)
        self.ip_impl.add_subnet(self.l3_port_impl.tx_port, subnet)
        self.setup_ingress_egress_counters()

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if(self.l3_port_impl.is_svi):
            packet_count, byte_count = self.l2_ingress_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            packet_count, byte_count = self.l2_egress_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET, byte_count)

        packet_count, byte_count = self.l3_ingress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.l3_egress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET, byte_count)

        self.ip_impl.delete_host(self.l3_port_impl.tx_port, self.DIP)
        self.ip_impl.delete_subnet(self.l3_port_impl.tx_port, subnet)

    def _test_add_host_no_subnet(self):
        subnet = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_host(self.l3_port_impl.tx_port, self.DIP, self.l3_port_impl.reg_nh.mac_addr)
        self.ip_impl.delete_host(self.l3_port_impl.tx_port, self.DIP)

    def _test_add_host_spa(self):
        self.spa_mac_port = T.mac_port(self, self.device, T.TX_SLICE_REG, T.TX_IFG_REG,
                                       MAC_PORT_FIRST_SERDES, MAC_PORT_LAST_SERDES, None)
        self.spa_mac_port.activate()
        self.spa_sys_port = T.system_port(self, self.device, 0x100, self.spa_mac_port)
        self.spa_port = T.spa_port(self, self.device, 0x100)
        self.spa_port.add(self.spa_sys_port)
        self.spa_port.hld_obj.set_member_transmit_enabled(self.spa_sys_port.hld_obj, True)
        self.spa_eth_port = T.sa_ethernet_port(self, self.device, self.spa_port, None)
        self.setup_ingress_egress_counters()

        if(self.l3_port_impl.is_svi):
            self.tx_l2_ac_spa = T.l2_ac_port(self, self.device, 0x1000, None,
                                             self.topology.tx_switch, self.spa_eth_port, self.l3_port_impl.reg_nh.mac_addr)
            self.l2_spa_counter = self.device.create_counter(1)
            self.tx_l2_ac_spa.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.l2_spa_counter)
            self.tx_l3_spa = self.l3_port_impl.tx_port
            self.NH_SPA_MAC = self.l3_port_impl.reg_nh.mac_addr
            self.l3_spa_counter = self.l3_egress_counter
            new_packet = self.EXPECTED_OUTPUT_PACKET
        else:
            self.L3_SPA_MAC = T.mac_addr('00:42:43:44:45:47')
            self.NH_SPA_MAC = T.mac_addr('00:42:43:44:45:48')

            self.tx_l3_ac_spa = T.l3_ac_port(self, self.device,
                                             0x200, self.spa_eth_port, self.topology.vrf, self.L3_SPA_MAC)
            self.nh_spa = T.next_hop(self, self.device, 0x612, self.NH_SPA_MAC, self.tx_l3_ac_spa)
            self.l3_spa_counter = self.device.create_counter(1)
            self.tx_l3_ac_spa.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.l3_spa_counter)
            self.tx_l3_spa = self.tx_l3_ac_spa
            new_packet = deepcopy(self.EXPECTED_OUTPUT_PACKET)
            new_packet[Ether].dst = self.NH_SPA_MAC.addr_str
            new_packet[Ether].src = self.L3_SPA_MAC.addr_str

        subnet = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_subnet(self.tx_l3_spa, subnet)
        self.ip_impl.add_host(self.tx_l3_spa, self.DIP, self.NH_SPA_MAC)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          new_packet, T.TX_SLICE_REG, T.TX_IFG_REG, MAC_PORT_FIRST_SERDES)

        if(self.l3_port_impl.is_svi):
            packet_count, byte_count = self.l2_ingress_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            packet_count, byte_count = self.l2_spa_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, new_packet, byte_count)

        packet_count, byte_count = self.l3_ingress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.l3_spa_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, new_packet, byte_count)

        self.ip_impl.delete_host(self.tx_l3_spa, self.DIP)
        self.ip_impl.delete_subnet(self.tx_l3_spa, subnet)

    def _test_add_host_wo_subnet(self):
        self.ip_impl.add_host(self.l3_port_impl.tx_port, self.DIP, self.l3_port_impl.reg_nh.mac_addr)
        self.ip_impl.delete_host(self.l3_port_impl.tx_port, self.DIP)

    def _test_add_subnet(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_subnet(self.l3_port_impl.tx_port, prefix)
        self.ip_impl.delete_subnet(self.l3_port_impl.tx_port, prefix)

    def _test_route_default(self, disable_rx=False, disable_tx=False):
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, self.l3_port_impl.serdes_def)

        if(not self.l3_port_impl.is_svi):
            if(disable_rx):
                self.l3_port_impl.rx_port.hld_obj.disable()
                U.run_and_drop(self, self.device,
                               self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

            if(disable_tx):
                self.l3_port_impl.tx_port_def.hld_obj.disable()
                U.run_and_drop(self, self.device,
                               self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def _test_delete_vrf(self):

        try:
            # Try to destroy the vrf when a L3 AC port is using it
            # This should fail
            self.topology.vrf.destroy()
            self.assertFail()
        except sdk.BaseException:
            pass

        # Try to destroy the vrf when a L3 AC port is not using it
        # This should pass
        self.topology.vrf2.destroy()

    def _test_destroy_route(self, disable_rx=False, disable_tx=False):
        self._test_route_single_fec(disable_rx, disable_tx)
        if not disable_rx and not disable_tx:
            self._test_route_default()

    def _test_route_existing_entry(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, ip_routing_base.PRIVATE_DATA)

        routing_info = self.ip_impl.get_routing_entry(self.topology.vrf, prefix)
        self.assertFalse(routing_info.is_host)
        self.assertEqual(routing_info.l3_dest.this, self.l3_port_impl.reg_fec.hld_obj.this)
        self.assertEqual(routing_info.user_data, ip_routing_base.PRIVATE_DATA)

        try:
            self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, ip_routing_base.PRIVATE_DATA)
            self.assertFail()
        except sdk.BaseException:
            pass

        self.ip_impl.get_routing_entry(self.topology.vrf, prefix)

    def _test_get_host_route(self):
        subnet = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_subnet(self.l3_port_impl.tx_port, subnet)
        self.ip_impl.add_host(self.l3_port_impl.tx_port, self.DIP, self.l3_port_impl.reg_nh.mac_addr)

        routing_info = self.ip_impl.get_route(self.topology.vrf, self.DIP)
        self.assertTrue(routing_info.is_host)

        self.ip_impl.delete_host(self.l3_port_impl.tx_port, self.DIP)
        self.ip_impl.delete_subnet(self.l3_port_impl.tx_port, subnet)

    def _test_get_hosts(self):
        subnets = []
        for dip in self.SUBNETS_HOSTS.keys():
            mac = self.SUBNETS_HOSTS[dip]
            subnet = self.ip_impl.build_prefix(dip, length=16)
            self.ip_impl.add_subnet(self.l3_port_impl.tx_port, subnet)
            self.ip_impl.add_host(self.l3_port_impl.tx_port, dip, mac)
            subnets.append(subnet)

        for dip in self.SUBNETS_HOSTS.keys():
            res_mac = self.ip_impl.get_host(self.l3_port_impl.tx_port, dip)
            self.assertEqual(res_mac.flat, self.SUBNETS_HOSTS[dip].hld_obj.flat)

        # cleanup
        for idx, dip in enumerate(self.SUBNETS_HOSTS.keys()):
            subnet = subnets[idx]
            self.ip_impl.delete_host(self.l3_port_impl.tx_port, dip)
            self.ip_impl.delete_subnet(self.l3_port_impl.tx_port, subnet)

    def _test_get_route(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_route(self.topology.vrf, prefix,
                               self.l3_port_impl.reg_fec,
                               ip_routing_base.PRIVATE_DATA)

        routing_info = self.ip_impl.get_route(self.topology.vrf, self.DIP)
        self.assertFalse(routing_info.is_host)
        self.assertEqual(routing_info.l3_dest.this, self.l3_port_impl.reg_fec.hld_obj.this)
        self.assertEqual(routing_info.user_data, ip_routing_base.PRIVATE_DATA)

        self.ip_impl.delete_route(self.topology.vrf, prefix)
        self.destroy_default_route()

        try:
            self.ip_impl.get_route(self.topology.vrf, self.DIP)
            self.assertFail()
        except sdk.BaseException:
            pass

        self.add_default_route()

    def _test_get_routing_entry(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, ip_routing_base.PRIVATE_DATA)

        routing_info = self.ip_impl.get_routing_entry(self.topology.vrf, prefix)
        self.assertFalse(routing_info.is_host)
        self.assertEqual(routing_info.l3_dest.this, self.l3_port_impl.reg_fec.hld_obj.this)
        self.assertEqual(routing_info.user_data, ip_routing_base.PRIVATE_DATA)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

        try:
            self.ip_impl.get_routing_entry(self.topology.vrf, prefix)
            self.assertFail()
        except sdk.BaseException:
            pass

    def _test_get_routing_entry_with_class_id(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        pref_dests = [
            (sdk.la_route_entry_action_e_ADD,
             prefix,
             self.l3_port_impl.reg_fec.hld_obj,
             ip_routing_base.CLASS_ID,
             ip_routing_base.PRIVATE_DATA,
             False)]
        self.do_ip_route_bulk_updates(self.topology.vrf, pref_dests)

        routing_info = self.ip_impl.get_routing_entry(self.topology.vrf, prefix)
        self.assertFalse(routing_info.is_host)
        self.assertEqual(routing_info.l3_dest.this, self.l3_port_impl.reg_fec.hld_obj.this)
        self.assertEqual(routing_info.user_data, ip_routing_base.PRIVATE_DATA)
        self.assertEqual(routing_info.class_id, ip_routing_base.CLASS_ID)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

        try:
            self.ip_impl.get_routing_entry(self.topology.vrf, prefix)
            self.assertFail()
        except sdk.BaseException:
            pass

    def _test_get_subnets(self):
        lst_subnets = []
        for dip in self.SUBNETS_HOSTS.keys():
            subnet = self.ip_impl.build_prefix(dip, length=16)
            lst_subnets.append(subnet)
            self.ip_impl.add_subnet(self.l3_port_impl.tx_port, subnet)

        try:
            self.ip_impl.add_subnet(self.l3_port_impl.tx_port, lst_subnets[0])
            self.assertFail()
        except sdk.BaseException:
            pass

        res_subnets = self.ip_impl.get_subnets(self.l3_port_impl.tx_port)

        # Check results
        self.assertEqual(len(res_subnets), len(lst_subnets))
        for i in range(0, len(res_subnets)):
            self.assertEqual(res_subnets[i].addr.b_addr, lst_subnets[i].addr.b_addr)

    def _test_change_mac(self, disable_rx=False, disable_tx=False):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, ip_routing_base.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        # Change rx port's mac address
        self.l3_port_impl.rx_port.hld_obj.set_mac(NEW_PORT_MAC.hld_obj)

        # Rerun
        new_packet = deepcopy(self.INPUT_PACKET)
        new_packet[Ether].dst = NEW_PORT_MAC.addr_str
        U.run_and_compare(self, self.device,
                          new_packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if (self.l3_port_impl.is_svi):
            self.l3_port_impl.rx_port.hld_obj.set_mac(T.RX_SVI_MAC.hld_obj)
        else:
            self.l3_port_impl.rx_port.hld_obj.set_mac(T.RX_L3_AC_MAC.hld_obj)

        # Change tx port's mac address
        self.l3_port_impl.tx_port.hld_obj.set_mac(NEW_TX_PORT_MAC.hld_obj)

        new_packet = deepcopy(self.EXPECTED_OUTPUT_PACKET)
        new_packet[Ether].src = NEW_TX_PORT_MAC.addr_str
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          new_packet, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if (self.l3_port_impl.is_svi == False):
            if disable_tx:
                self.l3_port_impl.tx_port.hld_obj.disable()
                U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

            if disable_rx:
                self.l3_port_impl.rx_port.hld_obj.disable()
                U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # Cleanup
        self.ip_impl.delete_route(self.topology.vrf, prefix)

    def _test_change_vrf(self, disable_rx=False, disable_tx=False):

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, ip_routing_base.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        # Change rx port vrf
        self.l3_port_impl.rx_port.hld_obj.set_vrf(self.topology.vrf2.hld_obj)
        NH_L3_AC_REG_GID2 = 0x612
        NH_L3_AC_REG_MAC2 = T.mac_addr('00:73:74:75:76:77')

        self.topology.tx_switch.hld_obj.set_mac_entry(
            NH_L3_AC_REG_MAC2.hld_obj,
            self.topology.tx_l2_ac_port_reg.hld_obj,
            sdk.LA_MAC_AGING_TIME_NEVER)

        # Change tx port NH
        nh_l3_ac_reg2 = T.next_hop(
            self.topology.testcase,
            self.topology.device,
            NH_L3_AC_REG_GID2,
            NH_L3_AC_REG_MAC2,
            self.l3_port_impl.tx_port)
        reg_fec2 = T.fec(self.topology.testcase, self.topology.device, nh_l3_ac_reg2)
        self.ip_impl.add_route(self.topology.vrf2, prefix, reg_fec2, ip_routing_base.PRIVATE_DATA)

        # Rerun with new VRF & different next hop
        new_packet = copy.deepcopy(self.EXPECTED_OUTPUT_PACKET)
        new_packet[Ether].dst = NH_L3_AC_REG_MAC2.addr_str

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          new_packet, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        # Change setting back to initial
        self.l3_port_impl.rx_port.hld_obj.set_vrf(self.topology.vrf.hld_obj)

        # Rerun with original VRF & next hop
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if (self.l3_port_impl.is_svi == False):
            if disable_tx:
                self.l3_port_impl.tx_port.hld_obj.disable()
                U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

            if disable_rx:
                self.l3_port_impl.rx_port.hld_obj.disable()
                U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # Cleanup
        self.ip_impl.delete_route(self.topology.vrf, prefix)
        self.ip_impl.delete_route(self.topology.vrf2, prefix)

    def _test_l3_ac_tag_change_vlan(self, disable_rx=False, disable_tx=False):
        px_vx_l3_ac = T.l3_ac_port(self,
                                   self.device,
                                   self.PORT_PxVx_GID,
                                   self.topology.rx_eth_port,
                                   self.topology.vrf,
                                   self.PORT_PxVx_MAC,
                                   self.PORT_PxVx_VID1)
        px_vx_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        px_vx_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, ip_routing_base.PRIVATE_DATA)
        egress_counter = self.device.create_counter(1)
        self.l3_port_impl.tx_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, egress_counter)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_PxVx, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        px_vx_l3_ac.hld_obj.set_service_mapping_vids(self.PORT_PxVx_VID1_2, sdk.LA_VLAN_ID_INVALID)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_PxVx_2, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)
        packet_count, byte_count = egress_counter.read(0,  # sub-counter index
                                                           True,  # force_update
                                                           True)  # clear_on_read
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_PxVx_2, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)
        packet_count, byte_count = egress_counter.read(0,  # sub-counter index
                                                           True,  # force_update
                                                           True)  # clear_on_read
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET, byte_count)
        if (self.l3_port_impl.is_svi == False):
            if disable_tx:
                self.l3_port_impl.tx_port.hld_obj.disable()
                U.run_and_drop(self, self.device, self.INPUT_PACKET_PxVx_2, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)
            if disable_rx:
                px_vx_l3_ac.hld_obj.disable()
                U.run_and_drop(self, self.device, self.INPUT_PACKET_PxVx_2, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        self.ip_impl.delete_route(self.topology.vrf, prefix)
        px_vx_l3_ac.destroy()

    def _test_l3_ac_tag_tag_change_vlan(self, disable_rx=False, disable_tx=False):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_route(self.topology.vrf, prefix,
                               self.l3_port_impl.reg_fec,
                               ip_routing_base.PRIVATE_DATA)
        egress_counter = self.device.create_counter(1)
        self.l3_port_impl.tx_port.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, egress_counter)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.l3_port_impl.rx_port.hld_obj.set_service_mapping_vids(VID1_2, VID2_2)
        U.run_and_compare(self, self.device,
                          self.CHANGE_VLAN_INPUT_PACKET_0, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)
        packet_count, byte_count = egress_counter.read(0,  # sub-counter index
                                                           True,  # force_update
                                                           True)  # clear_on_read
        U.run_and_compare(self, self.device,
                          self.CHANGE_VLAN_INPUT_PACKET_0, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)
        packet_count, byte_count = egress_counter.read(0,  # sub-counter index
                                                           True,  # force_update
                                                           True)  # clear_on_read
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET, byte_count)

        if(not self.l3_port_impl.is_svi):
            if(disable_rx):
                self.l3_port_impl.rx_port.hld_obj.disable()
                U.run_and_drop(self, self.device,
                               self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)
                packet_count, byte_count = egress_counter.read(0,  # sub-counter index
                                                               True,  # force_update
                                                               True)  # clear_on_read
                self.assertEqual(packet_count, 0)

            if(disable_tx):
                self.l3_port_impl.tx_port.hld_obj.disable()
                U.run_and_drop(self, self.device,
                               self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)
                packet_count, byte_count = egress_counter.read(0,  # sub-counter index
                                                               True,  # force_update
                                                               True)  # clear_on_read
                self.assertEqual(packet_count, 0)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

    def _test_l3_ac_tag_tag_change_vlan_mtu(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_route(self.topology.vrf, prefix,
                               self.l3_port_impl.reg_fec,
                               ip_routing_base.PRIVATE_DATA)
        self.l3_port_impl.rx_port.hld_obj.set_service_mapping_vids(VID1_2, VID2_2)
        MTU.run_mtu_test(self, self.device,
                         self.CHANGE_VLAN_INPUT_PACKET_0, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                         self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

    def _test_l3_ac_tag_tag_with_fallback_change_vlan(self):

        # Create L3 AC port with fallback
        rx_eth_port = T.ethernet_port(
            self,
            self.device,
            T.RX_SLICE,
            T.RX_IFG,
            SYS_PORT_GID,
            SERDES,
            SERDES)
        ac_profile = T.ac_profile(self, self.device, with_fallback=True)
        rx_eth_port.set_ac_profile(ac_profile)

        rx_ac_port = T.l3_ac_port(
            self,
            self.device,
            AC_PORT_GID,
            rx_eth_port,
            self.topology.vrf,
            PORT_MAC_ADDR,
            RX_AC_PORT_VID1)

        rx_ac_port.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)
        rx_ac_port.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV6_UC, True)

        # Run packet
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_route(self.topology.vrf, prefix,
                               self.l3_port_impl.reg_fec,
                               ip_routing_base.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.CHANGE_VLAN_INPUT_PACKET_1, T.RX_SLICE, T.RX_IFG, SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        # Change the port's tags
        rx_ac_port.hld_obj.set_service_mapping_vids(RX_AC_PORT_VID1_2, sdk.LA_VLAN_ID_INVALID)

        # Packet should still come out the same
        U.run_and_compare(self, self.device,
                          self.CHANGE_VLAN_INPUT_PACKET_2, T.RX_SLICE, T.RX_IFG, SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

    def _test_route_l3_drop_adj_non_inject(self):
        # Setup punt and trap
        pi_port_serdes = T.get_device_next4_first_serdes(self.INJECT_PIF_FIRST)
        pi_port = T.punt_inject_port(
            self,
            self.device,
            self.INJECT_SLICE,
            self.INJECT_IFG,
            self.INJECT_SP_GID,
            pi_port_serdes,
            PUNT_INJECT_PORT_MAC_ADDR)

        inj_port_serdes = T.get_device_next5_first_serdes(self.INJECT_PIF_FIRST)
        inj_port = T.punt_inject_port(
            self,
            self.device,
            T.RX_SLICE,
            T.RX_IFG,
            self.INJECT_SP_GID2,
            inj_port_serdes,
            PUNT_INJECT_PORT_MAC_ADDR)

        punt_dest = T.create_l2_punt_destination(self, self.device, T.L2_PUNT_DESTINATION2_GID, pi_port, HOST_MAC_ADDR, PUNT_VLAN)

        cnt_drop_adj_non = self.device.create_counter(1)
        # Set l3_drop_adj_non_inject trap with priority=0 and skip_non_inject=True
        self.device.set_trap_configuration(sdk.LA_EVENT_L3_DROP_ADJ_NON_INJECT, 0,
                                           cnt_drop_adj_non, punt_dest, True, False, True, 0)

        nh_null = self.l3_port_impl.glean_null_nh
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, nh_null, ip_routing_base.PRIVATE_DATA)

        nh_null.hld_obj.set_nh_type(sdk.la_next_hop.nh_type_e_DROP)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.PUNT_PACKET_L3_DROP_ADJ_NON_INJECT, self.INJECT_SLICE, self.INJECT_IFG, self.INJECT_PIF_FIRST)

        packets, bytes = cnt_drop_adj_non.read(0, True, True)
        self.assertEqual(packets, 1)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

    def _test_route_l3_user_trap_adj(self, user_trap_num=1):
        # Setup punt and trap
        pi_port = T.punt_inject_port(
            self,
            self.device,
            self.INJECT_SLICE,
            self.INJECT_IFG,
            self.INJECT_SP_GID,
            self.INJECT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        inj_port = T.punt_inject_port(
            self,
            self.device,
            T.RX_SLICE,
            T.RX_IFG,
            self.INJECT_SP_GID2,
            self.INJECT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        punt_dest = T.create_l2_punt_destination(self, self.device, T.L2_PUNT_DESTINATION2_GID, pi_port, HOST_MAC_ADDR, PUNT_VLAN)

        cnt_user_trap_adj = self.device.create_counter(1)
        nh_null = self.l3_port_impl.glean_null_nh
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        # Set l3_user_trap_adj trap with priority=1 and skip_non_inject=False
        if user_trap_num == 1:
            self.device.set_trap_configuration(sdk.LA_EVENT_L3_USER_TRAP1, 1, cnt_user_trap_adj, punt_dest, False, False, True, 0)
            nh_null.hld_obj.set_nh_type(sdk.la_next_hop.nh_type_e_USER_TRAP1)
        else:
            if user_trap_num == 2:
                self.device.set_trap_configuration(
                    sdk.LA_EVENT_L3_USER_TRAP2,
                    1,
                    cnt_user_trap_adj,
                    punt_dest,
                    False,
                    False,
                    True,
                    0)
                nh_null.hld_obj.set_nh_type(sdk.la_next_hop.nh_type_e_USER_TRAP2)

        self.ip_impl.add_route(self.topology.vrf, prefix, nh_null, ip_routing_base.PRIVATE_DATA)

        if user_trap_num == 1:
            U.run_and_compare(self, self.device,
                              self.INPUT_INJECT_UP_PACKET, T.RX_SLICE, T.RX_IFG, self.INJECT_PIF_FIRST,
                              self.PUNT_PACKET_L3_USER_TRAP1_ADJ, self.INJECT_SLICE, self.INJECT_IFG, self.INJECT_PIF_FIRST)
        else:
            if user_trap_num == 2:
                U.run_and_compare(self, self.device,
                                  self.INPUT_INJECT_UP_PACKET, T.RX_SLICE, T.RX_IFG, self.INJECT_PIF_FIRST,
                                  self.PUNT_PACKET_L3_USER_TRAP2_ADJ, self.INJECT_SLICE, self.INJECT_IFG, self.INJECT_PIF_FIRST)

        packets, bytes = cnt_user_trap_adj.read(0, True, True)
        self.assertEqual(packets, 1)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

    def _test_route_l3_drop_adj(self):
        # Setup punt and trap
        pi_port = T.punt_inject_port(
            self,
            self.device,
            self.INJECT_SLICE,
            self.INJECT_IFG,
            self.INJECT_SP_GID,
            self.INJECT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        inj_port_serdes = T.get_device_next2_first_serdes(self.INJECT_PIF_FIRST)
        inj_port = T.punt_inject_port(
            self,
            self.device,
            T.RX_SLICE,
            T.RX_IFG,
            self.INJECT_SP_GID2,
            inj_port_serdes,
            PUNT_INJECT_PORT_MAC_ADDR)

        punt_dest = T.create_l2_punt_destination(self, self.device, T.L2_PUNT_DESTINATION2_GID, pi_port, HOST_MAC_ADDR, PUNT_VLAN)

        cnt_drop_adj = self.device.create_counter(1)
        # Set l3_drop_adj trap with priority=1 and skip_non_inject=False
        self.device.set_trap_configuration(sdk.LA_EVENT_L3_DROP_ADJ, 1, cnt_drop_adj, punt_dest, False, False, True, 0)

        nh_null = self.l3_port_impl.glean_null_nh
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, nh_null, ip_routing_base.PRIVATE_DATA)

        nh_null.hld_obj.set_nh_type(sdk.la_next_hop.nh_type_e_DROP)
        U.run_and_compare(self, self.device,
                          self.INPUT_INJECT_UP_PACKET, T.RX_SLICE, T.RX_IFG, self.INJECT_PIF_FIRST,
                          self.PUNT_PACKET_L3_DROP_ADJ, self.INJECT_SLICE, self.INJECT_IFG, self.INJECT_PIF_FIRST)

        packets, bytes = cnt_drop_adj.read(0, True, True)
        self.assertEqual(packets, 1)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

    def _test_route_l3_drop_adj_pif_counter(self):
        # Setup punt and trap
        pi_port = T.punt_inject_port(
            self,
            self.device,
            self.INJECT_SLICE,
            self.INJECT_IFG,
            self.INJECT_SP_GID,
            self.INJECT_PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        inj_port_serdes = T.get_device_out_next_first_serdes(self.INJECT_PIF_FIRST)
        inj_port = T.punt_inject_port(
            self,
            self.device,
            T.RX_SLICE,
            T.RX_IFG,
            self.INJECT_SP_GID2,
            inj_port_serdes,
            PUNT_INJECT_PORT_MAC_ADDR)

        punt_dest = T.create_l2_punt_destination(self, self.device, T.L2_PUNT_DESTINATION2_GID, pi_port, HOST_MAC_ADDR, PUNT_VLAN)

        counter_set_size = self.device.get_limit(sdk.limit_type_e_COUNTER_SET__MAX_PIF_COUNTER_OFFSET)
        cnt_drop_adj = self.device.create_counter(counter_set_size)
        # Set l3_drop_adj trap with priority=1 and skip_non_inject=False
        self.device.set_trap_configuration(sdk.LA_EVENT_L3_DROP_ADJ, 1, cnt_drop_adj, punt_dest, False, False, True, 0)

        nh_null = self.l3_port_impl.glean_null_nh
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, nh_null, ip_routing_base.PRIVATE_DATA)

        nh_null.hld_obj.set_nh_type(sdk.la_next_hop.nh_type_e_DROP)
        U.run_and_compare(self, self.device,
                          self.INPUT_INJECT_UP_PACKET, T.RX_SLICE, T.RX_IFG, self.INJECT_PIF_FIRST,
                          self.PUNT_PACKET_L3_DROP_ADJ, self.INJECT_SLICE, self.INJECT_IFG, self.INJECT_PIF_FIRST)

        counts = get_trap_pif_packet_counts(self.device, sdk.LA_EVENT_L3_DROP_ADJ)
        self.assertEqual(sum(counts), 1)
        self.assertEqual(counts[self.INJECT_PIF_FIRST], 1)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

    def _test_illegal_dip(self, dip):

        prefix = self.ip_impl.get_default_prefix()
        prefix.length = 10
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, ip_routing_base.PRIVATE_DATA)

        packet = U.packet_edit_layer(self.INPUT_PACKET, 3, 'dst', dip)

        U.run_and_drop(self, self.device, packet, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # Cleanup
        self.ip_impl.delete_route(self.topology.vrf, prefix)

    def _test_route_longer_prefix(self, disable_rx=False, disable_tx=False):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, ip_routing_base.PRIVATE_DATA)
        long_prefix = self.ip_impl.build_prefix(self.DIP, length=24)

        self.ip_impl.add_route(self.topology.vrf, long_prefix,
                               self.l3_port_impl.ext_nh,
                               ip_routing_base.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_EXTRA_OUTPUT_PACKET, T.TX_SLICE_EXT,
                          T.TX_IFG_EXT, self.l3_port_impl.serdes_ext)

        if(not self.l3_port_impl.is_svi):
            if(disable_rx):
                self.l3_port_impl.rx_port.hld_obj.disable()
                U.run_and_drop(self, self.device,
                               self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

            if(disable_tx):
                self.l3_port_impl.tx_port_ext.hld_obj.disable()
                U.run_and_drop(self, self.device,
                               self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        self.ip_impl.delete_route(self.topology.vrf, prefix)
        self.ip_impl.delete_route(self.topology.vrf, long_prefix)

    def prepare_ip_route_bulk_updates_vec(self, pref_dests):
        prefixes_update_vec = []

        for perf_dest in pref_dests:
            if len(perf_dest) == 3:
                action, prefix, dest = perf_dest
                class_id = ip_routing_base.CLASS_ID
                private_data = ip_routing_base.PRIVATE_DATA
                latency_sensitive = False
            elif len(perf_dest) == 4:
                action, prefix, dest, private_data = perf_dest
                class_id = ip_routing_base.CLASS_ID
                latency_sensitive = False
            else:
                action, prefix, dest, class_id, private_data, latency_sensitive = perf_dest

            prefix_update = self.ip_impl.ip_route_bulk_entry(action, prefix, dest, class_id, private_data, latency_sensitive)
            prefixes_update_vec.append(prefix_update)

        return prefixes_update_vec

    def program_ip_route_bulk(self, vrf, prefixes_update_vec):
        out_count_success = self.ip_impl.ip_route_bulk_updates(vrf, prefixes_update_vec)
        self.assertEqual(out_count_success, len(prefixes_update_vec))

    def do_ip_route_bulk_updates(self, vrf, pref_dests):
        prefixes_update_vec = self.prepare_ip_route_bulk_updates_vec(pref_dests)
        self.program_ip_route_bulk(vrf, prefixes_update_vec)

    def do_setup_vrf_redirect(self, vrf_id):
        vrf = self.device.create_vrf(vrf_id)
        vrf_redir_dest = self.device.create_vrf_redirect_destination(vrf)
        with self.assertRaises(sdk.BusyException):
            vrf_redir_dest = self.device.create_vrf_redirect_destination(vrf)
        vrf_redir_dest = self.device.get_vrf_redirect_destination(vrf)
        return vrf, vrf_redir_dest

    def _test_add_prefix_fec_dependancy_bulk(self, prefix):
        self.destroy_default_route()

        fec_l3_ac_reg = self.device.create_l3_fec(self.l3_port_impl.reg_nh.hld_obj)
        pref_dests = [(sdk.la_route_entry_action_e_ADD, prefix, fec_l3_ac_reg)]
        self.do_ip_route_bulk_updates(self.topology.vrf, pref_dests)
        try:
            self.device.destroy(fec_l3_ac_reg)
            self.assertFail()
        except sdk.BaseException:
            pass

        pref_dests = [(sdk.la_route_entry_action_e_DELETE, prefix, 0)]
        self.do_ip_route_bulk_updates(self.topology.vrf, pref_dests)
        self.device.destroy(fec_l3_ac_reg)

    def _test_modify_prefix_fec_dependancy_bulk(self, prefix):
        self.destroy_default_route()

        fec_l3_ac_reg1 = self.device.create_l3_fec(self.l3_port_impl.reg_nh.hld_obj)
        fec_l3_ac_reg2 = self.device.create_l3_fec(self.l3_port_impl.reg_nh.hld_obj)
        pref_dests = [(sdk.la_route_entry_action_e_ADD, prefix, fec_l3_ac_reg1)]
        self.do_ip_route_bulk_updates(self.topology.vrf, pref_dests)
        try:
            self.device.destroy(fec_l3_ac_reg1)
            self.assertFail()
        except sdk.BaseException:
            pass

        pref_dests = [(sdk.la_route_entry_action_e_MODIFY, prefix, fec_l3_ac_reg2)]
        self.do_ip_route_bulk_updates(self.topology.vrf, pref_dests)
        try:
            self.device.destroy(fec_l3_ac_reg2)
            self.assertFail()
        except sdk.BaseException:
            pass

        self.device.destroy(fec_l3_ac_reg1)

        pref_dests = [(sdk.la_route_entry_action_e_DELETE, prefix, 0)]
        self.do_ip_route_bulk_updates(self.topology.vrf, pref_dests)
        self.device.destroy(fec_l3_ac_reg2)

    def _test_route_longer_prefix_bulk(self):
        short_prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        long_prefix = self.ip_impl.build_prefix(self.DIP, length=24)
        def_prefix = self.ip_impl.get_default_prefix()
        fec_dest = self.l3_port_impl.reg_fec.hld_obj.get_destination()
        ext_nh_dest = self.l3_port_impl.ext_nh.hld_obj
        def_dest = self.l3_port_impl.def_nh.hld_obj

        self.destroy_default_route()

        pref_dests = [(sdk.la_route_entry_action_e_ADD, short_prefix, fec_dest),
                      (sdk.la_route_entry_action_e_ADD, long_prefix, ext_nh_dest),
                      (sdk.la_route_entry_action_e_ADD, def_prefix, def_dest)]
        self.do_ip_route_bulk_updates(self.topology.vrf, pref_dests)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_EXTRA_OUTPUT_PACKET, T.TX_SLICE_EXT,
                          T.TX_IFG_EXT, self.l3_port_impl.serdes_ext)

        pref_dests = [(sdk.la_route_entry_action_e_MODIFY, short_prefix, ext_nh_dest),
                      (sdk.la_route_entry_action_e_MODIFY, long_prefix, fec_dest),
                      (sdk.la_route_entry_action_e_MODIFY, def_prefix, fec_dest)]
        self.do_ip_route_bulk_updates(self.topology.vrf, pref_dests)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_DEF_RTE, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_DEF_RTE, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        pref_dests = [(sdk.la_route_entry_action_e_DELETE, short_prefix, 0),
                      (sdk.la_route_entry_action_e_DELETE, long_prefix, 0),
                      (sdk.la_route_entry_action_e_DELETE, def_prefix, 0)]
        self.do_ip_route_bulk_updates(self.topology.vrf, pref_dests)

        self.add_default_route()

    def _test_route_interface_prefix_bulk(self):
        prefix1 = self.ip_impl.build_prefix(self.DIP, length=32)
        dest1 = self.topology.forus_dest.hld_obj
        prefix2 = self.ip_impl.build_prefix(self.DIP0, length=24)
        dest2 = self.l3_port_impl.reg_fec.hld_obj.get_destination()
        prefix3 = self.ip_impl.build_prefix(self.DIP255, length=32)
        dest3 = self.l3_port_impl.reg_fec.hld_obj.get_destination()

        pref_dests = [(sdk.la_route_entry_action_e_ADD, prefix1, dest1),
                      (sdk.la_route_entry_action_e_ADD, prefix2, dest2),
                      (sdk.la_route_entry_action_e_ADD, prefix3, dest3)]
        self.do_ip_route_bulk_updates(self.topology.vrf, pref_dests)

        pref_dests = [(sdk.la_route_entry_action_e_DELETE, prefix1, 0),
                      (sdk.la_route_entry_action_e_DELETE, prefix2, 0),
                      (sdk.la_route_entry_action_e_DELETE, prefix3, 0)]
        self.do_ip_route_bulk_updates(self.topology.vrf, pref_dests)

    def _test_route_max_length_prefix_bulk(self, prefix):
        dest1 = self.topology.nh_l3_ac_reg.hld_obj
        dest2 = self.topology.nh_l3_ac_ext.hld_obj

        pref_dests = [(sdk.la_route_entry_action_e_ADD, prefix, dest1)]
        self.do_ip_route_bulk_updates(self.topology.vrf, pref_dests)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        pref_dests = [(sdk.la_route_entry_action_e_MODIFY, prefix, dest2)]
        self.do_ip_route_bulk_updates(self.topology.vrf, pref_dests)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_EXTRA_OUTPUT_PACKET, T.TX_SLICE_EXT,
                          T.TX_IFG_EXT, T.FIRST_SERDES_L3_EXT)

        pref_dests = [(sdk.la_route_entry_action_e_DELETE, prefix, 0)]
        self.do_ip_route_bulk_updates(self.topology.vrf, pref_dests)

    def _test_route_max_length_latency_sensitive_prefix_bulk(self, prefix):
        dest1 = self.topology.nh_l3_ac_reg.hld_obj
        dest2 = self.topology.nh_l3_ac_ext.hld_obj
        private_data = ip_routing_base.PRIVATE_DATA

        pref_dests = [(sdk.la_route_entry_action_e_ADD, prefix, dest1, ip_routing_base.CLASS_ID, private_data, True)]
        self.do_ip_route_bulk_updates(self.topology.vrf, pref_dests)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG,
                          T.TX_IFG_REG, T.FIRST_SERDES_L3_REG)

        pref_dests = [(sdk.la_route_entry_action_e_MODIFY, prefix, dest2)]
        self.do_ip_route_bulk_updates(self.topology.vrf, pref_dests)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_EXTRA_OUTPUT_PACKET, T.TX_SLICE_EXT,
                          T.TX_IFG_EXT, T.FIRST_SERDES_L3_EXT)

        pref_dests = [(sdk.la_route_entry_action_e_DELETE, prefix, 0)]
        self.do_ip_route_bulk_updates(self.topology.vrf, pref_dests)

    def _test_route_latency_sensitive_prefix_same_bulk(self, prefix):
        dest1 = self.topology.nh_l3_ac_reg.hld_obj
        dest2 = self.topology.nh_l3_ac_ext.hld_obj
        private_data = ip_routing_base.PRIVATE_DATA

        pref_dests = [(sdk.la_route_entry_action_e_ADD, prefix, dest1, ip_routing_base.CLASS_ID, private_data, False),
                      (sdk.la_route_entry_action_e_ADD, prefix, dest2, ip_routing_base.CLASS_ID, private_data, True)]
        prefixes_update_vec = self.prepare_ip_route_bulk_updates_vec(pref_dests)

        try:
            out_count_success = self.ip_impl.ip_route_bulk_updates(self.topology.vrf, prefixes_update_vec)
            self.assertEqual(out_count_success, 1)
        except sdk.BaseException:
            pass

        pref_dests = [(sdk.la_route_entry_action_e_DELETE, prefix, 0)]
        prefixes_update_vec = self.prepare_ip_route_bulk_updates_vec(pref_dests)
        out_count_success = self.ip_impl.ip_route_bulk_updates(self.topology.vrf, prefixes_update_vec)
        self.assertEqual(out_count_success, 1)

        pref_dests = [(sdk.la_route_entry_action_e_ADD, prefix, dest2, ip_routing_base.CLASS_ID, private_data, True),
                      (sdk.la_route_entry_action_e_ADD, prefix, dest1, ip_routing_base.CLASS_ID, private_data, False)]
        prefixes_update_vec = self.prepare_ip_route_bulk_updates_vec(pref_dests)
        try:
            out_count_success = self.ip_impl.ip_route_bulk_updates(self.topology.vrf, prefixes_update_vec)
            self.assertEqual(out_count_success, 1)
        except sdk.BaseException:
            pass

    def _test_route_add_same_prefix_bulk(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        ext_nh_dest = self.l3_port_impl.ext_nh.hld_obj
        fec_dest = self.l3_port_impl.reg_fec.hld_obj.get_destination()
        def_dest = self.l3_port_impl.def_nh.hld_obj

        self.destroy_default_route()

        pref_dests = [(sdk.la_route_entry_action_e_ADD, prefix, ext_nh_dest),
                      (sdk.la_route_entry_action_e_ADD, prefix, fec_dest),
                      (sdk.la_route_entry_action_e_ADD, prefix, def_dest)]
        prefixes_update_vec = self.prepare_ip_route_bulk_updates_vec(pref_dests)
        try:
            out_count_success = self.ip_impl.ip_route_bulk_updates(self.topology.vrf, prefixes_update_vec)
            self.assertEqual(out_count_success, 1)
        except sdk.BaseException:
            pass

        pref_dests = [(sdk.la_route_entry_action_e_ADD, prefix, fec_dest)]
        prefixes_update_vec = self.prepare_ip_route_bulk_updates_vec(pref_dests)
        try:
            out_count_success = self.ip_impl.ip_route_bulk_updates(self.topology.vrf, prefixes_update_vec)
            self.assertFail()
        except sdk.BaseException:
            pass

    def _test_route_modify_same_prefix_bulk(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        ext_nh_dest = self.l3_port_impl.ext_nh.hld_obj
        fec_dest = self.l3_port_impl.reg_fec.hld_obj.get_destination()
        def_dest = self.l3_port_impl.def_nh.hld_obj

        self.destroy_default_route()
        pref_dests = [(sdk.la_route_entry_action_e_ADD, prefix, def_dest)]
        self.do_ip_route_bulk_updates(self.topology.vrf, pref_dests)

        pref_dests = [(sdk.la_route_entry_action_e_MODIFY, prefix, fec_dest),
                      (sdk.la_route_entry_action_e_MODIFY, prefix, ext_nh_dest)]
        prefixes_update_vec = self.prepare_ip_route_bulk_updates_vec(pref_dests)
        out_count_success = self.ip_impl.ip_route_bulk_updates(self.topology.vrf, prefixes_update_vec)
        self.assertEqual(out_count_success, 1)

        pref_dests = [(sdk.la_route_entry_action_e_MODIFY, prefix, fec_dest)]
        prefixes_update_vec = self.prepare_ip_route_bulk_updates_vec(pref_dests)
        out_count_success = self.ip_impl.ip_route_bulk_updates(self.topology.vrf, prefixes_update_vec)
        self.assertEqual(out_count_success, 1)

        pref_dests = [(sdk.la_route_entry_action_e_MODIFY, prefix, ext_nh_dest)]
        prefixes_update_vec = self.prepare_ip_route_bulk_updates_vec(pref_dests)
        out_count_success = self.ip_impl.ip_route_bulk_updates(self.topology.vrf, prefixes_update_vec)
        self.assertEqual(out_count_success, 1)

    def _test_route_delete_same_prefix_bulk(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        ext_nh_dest = self.l3_port_impl.ext_nh.hld_obj

        self.destroy_default_route()
        pref_dests = [(sdk.la_route_entry_action_e_ADD, prefix, ext_nh_dest)]
        self.do_ip_route_bulk_updates(self.topology.vrf, pref_dests)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_EXTRA_OUTPUT_PACKET, T.TX_SLICE_EXT,
                          T.TX_IFG_EXT, self.l3_port_impl.serdes_ext)

        pref_dests = [(sdk.la_route_entry_action_e_DELETE, prefix, 0),
                      (sdk.la_route_entry_action_e_DELETE, prefix, 0)]

        prefixes_update_vec = self.prepare_ip_route_bulk_updates_vec(pref_dests)
        try:
            out_count_success = self.ip_impl.ip_route_bulk_updates(self.topology.vrf, prefixes_update_vec)
            self.assertEqual(out_count_success, 1)
        except sdk.BaseException:
            pass

    def _test_route_longer_prefix_mtu(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, ip_routing_base.PRIVATE_DATA)
        long_prefix = self.ip_impl.build_prefix(self.DIP, length=24)

        self.ip_impl.add_route(self.topology.vrf, long_prefix,
                               self.l3_port_impl.ext_nh,
                               ip_routing_base.PRIVATE_DATA)

        MTU.run_mtu_test(self, self.device,
                         self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                         self.EXPECTED_EXTRA_OUTPUT_PACKET, T.TX_SLICE_EXT,
                         T.TX_IFG_EXT, self.l3_port_impl.serdes_ext)

        self.ip_impl.delete_route(self.topology.vrf, prefix)
        self.ip_impl.delete_route(self.topology.vrf, long_prefix)

    def _test_modify_host(self, disable_rx=False, disable_tx=False):
        subnet = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_subnet(self.l3_port_impl.tx_port, subnet)
        self.ip_impl.add_host(self.l3_port_impl.tx_port, self.DIP, self.l3_port_impl.reg_nh.mac_addr)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.ip_impl.modify_host(self.l3_port_impl.tx_port, self.DIP, self.l3_port_impl.def_nh.mac_addr)

        expected_packet = deepcopy(self.EXPECTED_OUTPUT_PACKET)
        out_slice = T.TX_SLICE_REG
        tx_ifg = T.TX_IFG_REG
        serdes = serdes = self.l3_port_impl.serdes_reg
        if (self.l3_port_impl.is_svi):
            expected_packet[Ether].dst = T.NH_SVI_DEF_MAC.addr_str
            out_slice = T.TX_SLICE_DEF
            tx_ifg = T.TX_IFG_DEF
            serdes = self.l3_port_impl.serdes_def
        else:
            expected_packet[Ether].dst = T.NH_L3_AC_DEF_MAC.addr_str

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          expected_packet, out_slice, tx_ifg, serdes)

        if(not self.l3_port_impl.is_svi):
            if(disable_rx):
                self.l3_port_impl.rx_port.hld_obj.disable()
                U.run_and_drop(self, self.device,
                               self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)
            if(disable_tx):
                self.l3_port_impl.tx_port.hld_obj.disable()
                U.run_and_drop(self, self.device,
                               self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # Modify entry with unknown IP - should fail
        try:
            self.ip_impl.modify_host(self.l3_port_impl.tx_port, self.DIP_DEF_RTE, self.l3_port_impl.def_nh.mac_addr)
            self.fail()
        except sdk.BaseException as STATUS:
            self.assertEqual(STATUS.args[0], sdk.la_status_e_E_NOTFOUND)

    def _test_modify_route(self, disable_rx=False, disable_tx=False):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_route(self.topology.vrf, prefix,
                               self.l3_port_impl.reg_fec,
                               ip_routing_base.PRIVATE_DATA)

        self.ip_impl.modify_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec)
        self.ip_impl.modify_route(self.topology.vrf, prefix, self.l3_port_impl.ext_nh)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_EXTRA_OUTPUT_PACKET, T.TX_SLICE_EXT, T.TX_IFG_EXT, self.l3_port_impl.serdes_ext)

        self.ip_impl.modify_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        # update the default route to point to the regular fec entry
        # send a input packet that hits the default route
        def_prefix = self.ip_impl.get_default_prefix()
        self.ip_impl.modify_route(self.topology.vrf, def_prefix, self.l3_port_impl.reg_fec)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_DEF_RTE, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_DEF_RTE, T.TX_SLICE_REG,
                          T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if(not self.l3_port_impl.is_svi):
            if(disable_rx):
                self.l3_port_impl.rx_port.hld_obj.disable()
                U.run_and_drop(self, self.device,
                               self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

            if(disable_tx):
                self.l3_port_impl.tx_port.hld_obj.disable()
                U.run_and_drop(self, self.device,
                               self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        # restore the default route to point to the default nh
        self.ip_impl.modify_route(self.topology.vrf, def_prefix, self.l3_port_impl.def_nh)

        # Delete the user configured default route and try to modify the route
        self.destroy_default_route()

        try:
            self.ip_impl.modify_route(self.topology.vrf, def_prefix, self.l3_port_impl.reg_fec)
            self.assertFail()
        except sdk.BaseException:
            pass

        self.add_default_route()

        self.ip_impl.delete_route(self.topology.vrf, prefix)

    def _test_route_no_default(self):
        self.destroy_default_route()
        U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)
        self.add_default_route()

    def _test_remove_default_route(self):
        self._test_route_no_default()
        self._test_route_single_fec()

    def _test_route_set_active(self, disable_tx=False, disable_rx=False):
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, self.l3_port_impl.serdes_def)

        self.l3_port_impl.rx_port.hld_obj.set_active(False)
        U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        self.l3_port_impl.rx_port.hld_obj.set_active(True)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, self.l3_port_impl.serdes_def)

        self.l3_port_impl.tx_port_def.hld_obj.set_active(False)
        U.run_and_drop(self, self.device, self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        self.l3_port_impl.tx_port_def.hld_obj.set_active(True)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, self.l3_port_impl.serdes_def)

        if(self.l3_port_impl.is_svi != True):
            if(disable_rx):
                self.l3_port_impl.rx_port.hld_obj.disable()
                U.run_and_drop(self, self.device,
                               self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

            if(disable_tx):
                self.l3_port_impl.tx_port_def.hld_obj.disable()
                U.run_and_drop(self, self.device,
                               self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def _test_route_single_fec(self, disable_rx=False, disable_tx=False):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_route(self.topology.vrf, prefix,
                               self.l3_port_impl.reg_fec,
                               ip_routing_base.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if(self.l3_port_impl.is_svi != True):
            if(disable_rx):
                self.l3_port_impl.rx_port.hld_obj.disable()
                U.run_and_drop(self, self.device,
                               self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

            if(disable_tx):
                self.l3_port_impl.tx_port.hld_obj.disable()
                U.run_and_drop(self, self.device,
                               self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

    def _test_route_single_nh(self, disable_rx=False, disable_tx=False):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_nh, ip_routing_base.PRIVATE_DATA)

        self.setup_ingress_egress_counters()
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if(self.l3_port_impl.is_svi):
            packet_count, byte_count = self.l2_ingress_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            packet_count, byte_count = self.l2_egress_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET, byte_count)

        packet_count, byte_count = self.l3_ingress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.l3_egress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET, byte_count)

        if(self.l3_port_impl.is_svi != True):
            if(disable_rx):
                self.l3_port_impl.rx_port.hld_obj.disable()
                U.run_and_drop(self, self.device,
                               self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

            if(disable_tx):
                self.l3_port_impl.tx_port.hld_obj.disable()
                U.run_and_drop(self, self.device,
                               self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

    def _test_route_vxlan(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_nh, ip_routing_base.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_VXLAN, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_VXLAN, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

    def _test_route_update_mac(self, disable_rx=False, disable_tx=False):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, ip_routing_base.PRIVATE_DATA)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.topology.tx_switch.hld_obj.set_mac_entry(NH_MAC_MODIFIED.hld_obj, self.topology.tx_l2_ac_port_reg.hld_obj,
                                                      sdk.LA_MAC_AGING_TIME_NEVER)

        self.l3_port_impl.reg_nh.hld_obj.set_mac(NH_MAC_MODIFIED.hld_obj)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_WITH_UPDATED_MAC,
                          T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if(disable_rx):
            self.l3_port_impl.rx_port.hld_obj.disable()
            U.run_and_drop(self, self.device,
                           self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        if(disable_tx):
            self.l3_port_impl.tx_port.hld_obj.disable()
            U.run_and_drop(self, self.device,
                           self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

    def _test_route_update_nh_mac(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, ip_routing_base.PRIVATE_DATA)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        # create inject-up port for tx_svi
        self.rcy_slice = 1
        print("rcy system port gid is ", self.topology.recycle_ports[1].sys_port.hld_obj.get_gid(), "slice is ", self.rcy_slice)
        self.inject_up_rcy_eth_port = T.sa_ethernet_port(self, self.device, self.topology.recycle_ports[self.rcy_slice].sys_port)
        self.tx_inject_up_l2ac_port = T.l2_ac_port(
            self,
            self.device,
            0x100,
            None,
            self.topology.tx_switch,
            self.inject_up_rcy_eth_port,
            T.RX_MAC,
            0x10,
            0xABC)
        # pop the two vlan tags in packet meant for recovering relay_id
        ive = sdk.la_vlan_edit_command()
        ive.num_tags_to_push = 0
        ive.num_tags_to_pop = 2
        self.tx_inject_up_l2ac_port.hld_obj.set_ingress_vlan_edit_command(ive)

        self.topology.tx_svi.hld_obj.set_inject_up_source_port(self.tx_inject_up_l2ac_port.hld_obj)
        self.topology.tx_switch.hld_obj.set_flood_destination(self.topology.tx_l2_ac_port_def.hld_obj)

        self.l3_port_impl.reg_nh.hld_obj.set_mac(NH_MAC_MODIFIED.hld_obj)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_WITH_UPDATED_MAC,
                          T.TX_SLICE_DEF, T.TX_IFG_DEF, self.l3_port_impl.serdes_def)

        self.topology.tx_switch.hld_obj.set_mac_entry(NH_MAC_MODIFIED.hld_obj, self.topology.tx_l2_ac_port_reg.hld_obj,
                                                      sdk.LA_MAC_AGING_TIME_NEVER)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET_WITH_UPDATED_MAC,
                          T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

    def _test_route_update_nh(self):
        # Setup punt and trap
        pi_port_serdes = T.get_device_next3_first_serdes(self.INJECT_PIF_FIRST)
        pi_port = T.punt_inject_port(
            self,
            self.device,
            self.INJECT_SLICE,
            self.INJECT_IFG,
            self.INJECT_SP_GID,
            pi_port_serdes,
            PUNT_INJECT_PORT_MAC_ADDR)

        punt_dest = T.create_l2_punt_destination(self, self.device, T.L2_PUNT_DESTINATION2_GID, pi_port, HOST_MAC_ADDR, PUNT_VLAN)

        priority = 0
        self._try_clear_trap(sdk.LA_EVENT_L3_GLEAN_ADJ)
        self.device.set_trap_configuration(sdk.LA_EVENT_L3_GLEAN_ADJ, priority, None, punt_dest, False, False, True, 0)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, ip_routing_base.PRIVATE_DATA)

        self.l3_port_impl.reg_nh.hld_obj.set_nh_type(sdk.la_next_hop.nh_type_e_NORMAL)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET,
                          T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.l3_port_impl.reg_nh.hld_obj.set_nh_type(sdk.la_next_hop.nh_type_e_GLEAN)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.PUNT_PACKET, self.INJECT_SLICE, self.INJECT_IFG, pi_port_serdes)

        self.l3_port_impl.reg_nh.hld_obj.set_nh_type(sdk.la_next_hop.nh_type_e_NORMAL)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        # Should be able to change to type DROP from type NORMAL
        self.l3_port_impl.reg_nh.hld_obj.set_nh_type(sdk.la_next_hop.nh_type_e_DROP)
        self.l3_port_impl.reg_nh.hld_obj.set_nh_type(sdk.la_next_hop.nh_type_e_NULL_)

        self.l3_port_impl.reg_fec.hld_obj.set_destination(self.l3_port_impl.glean_nh.hld_obj)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.PUNT_PACKET, self.INJECT_SLICE, self.INJECT_IFG, pi_port_serdes)

        self.l3_port_impl.glean_nh.hld_obj.set_nh_type(sdk.la_next_hop.nh_type_e_NORMAL)

        try:
            self.l3_port_impl.glean_nh.hld_obj.set_nh_type(sdk.la_next_hop.nh_type_e_NULL_)
            self.l3_port_impl.glean_nh.hld_obj.set_nh_type(sdk.la_next_hop.nh_type_e_DROP)
            self.assertFail()
        except sdk.BaseException:
            pass

        self.ip_impl.modify_route(self.topology.vrf, prefix, self.l3_port_impl.glean_null_nh)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.PUNT_PACKET, self.INJECT_SLICE, self.INJECT_IFG, pi_port_serdes)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

    def _test_route_change_nh_type(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.nh = T.next_hop(self, self.device, T.NH_SVI_REG_GID + 1, T.NH_SVI_REG_MAC, self.topology.tx_svi)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.nh, ip_routing_base.PRIVATE_DATA)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.nh.hld_obj.set_nh_type(sdk.la_next_hop.nh_type_e_DROP)
        self.ip_impl.delete_route(self.topology.vrf, prefix)
        self.nh.destroy()

        self.nh = T.next_hop(self, self.device, T.NH_SVI_REG_GID + 1, T.NH_SVI_REG_MAC, self.topology.tx_svi)
        self.topology.tx_switch.hld_obj.set_mac_entry(T.NH_SVI_REG_MAC.hld_obj, self.topology.tx_l2_ac_port_reg.hld_obj,
                                                      sdk.LA_MAC_AGING_TIME_NEVER)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.nh, ip_routing_base.PRIVATE_DATA)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.nh.hld_obj.set_nh_type(sdk.la_next_hop.nh_type_e_GLEAN)
        self.ip_impl.delete_route(self.topology.vrf, prefix)
        self.nh.destroy()

        self.nh = T.next_hop(self, self.device, T.NH_SVI_REG_GID + 1, T.NH_SVI_REG_MAC, self.topology.tx_svi)
        self.topology.tx_switch.hld_obj.set_mac_entry(T.NH_SVI_REG_MAC.hld_obj, self.topology.tx_l2_ac_port_reg.hld_obj,
                                                      sdk.LA_MAC_AGING_TIME_NEVER)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.nh, ip_routing_base.PRIVATE_DATA)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.nh.hld_obj.set_nh_type(sdk.la_next_hop.nh_type_e_GLEAN)
        self.nh.hld_obj.set_nh_type(sdk.la_next_hop.nh_type_e_NORMAL)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        self.ip_impl.delete_route(self.topology.vrf, prefix)
        self.nh.destroy()

    def _test_route_with_vlan(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, ip_routing_base.PRIVATE_DATA)

        tag = sdk.la_vlan_tag_t()
        tag.tpid = 0x8100
        tag.tci.fields.pcp = 0
        tag.tci.fields.dei = 0
        tag.tci.fields.vid = self.OUTPUT_VID
        self.l3_port_impl.tx_port.hld_obj.set_egress_vlan_tag(tag, sdk.LA_VLAN_TAG_UNTAGGED)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = self.OUTPUT_VID
        self.topology.tx_l2_ac_port_reg.hld_obj.set_egress_vlan_edit_command(eve)

        self.setup_ingress_egress_counters()

        U.run_and_compare(
            self,
            self.device,
            self.INPUT_PACKET,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.EXPECTED_OUTPUT_PACKET_WITH_VLAN,
            T.TX_SLICE_REG,
            T.TX_IFG_REG,
            self.l3_port_impl.serdes_reg)

        if (self.l3_port_impl.is_svi):
            packet_count, byte_count = self.l2_ingress_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            packet_count, byte_count = self.l2_egress_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_WITH_VLAN, byte_count)

        packet_count, byte_count = self.l3_ingress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.l3_egress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_WITH_VLAN, byte_count)

        # Remove the tag
        tag.tpid = 0
        tag.tci.fields.pcp = 0
        tag.tci.fields.dei = 0
        tag.tci.fields.vid = 0
        self.l3_port_impl.tx_port.hld_obj.set_egress_vlan_tag(tag, sdk.LA_VLAN_TAG_UNTAGGED)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 0
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = 0
        self.topology.tx_l2_ac_port_reg.hld_obj.set_egress_vlan_edit_command(eve)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if (self.l3_port_impl.is_svi):
            packet_count, byte_count = self.l2_ingress_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            packet_count, byte_count = self.l2_egress_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)

        packet_count, byte_count = self.l3_ingress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.l3_egress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET, byte_count)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

    def _test_route_with_vlan_vlan(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, ip_routing_base.PRIVATE_DATA)

        tag1 = sdk.la_vlan_tag_t()
        tag1.tpid = 0x88a8
        tag1.tci.fields.pcp = 0
        tag1.tci.fields.dei = 0
        tag1.tci.fields.vid = self.OUTPUT_VID1
        tag2 = sdk.la_vlan_tag_t()
        tag2.tpid = 0x8100
        tag2.tci.fields.pcp = 0
        tag2.tci.fields.dei = 0
        tag2.tci.fields.vid = self.OUTPUT_VID2
        self.l3_port_impl.tx_port.hld_obj.set_egress_vlan_tag(tag1, tag2)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 1
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = self.OUTPUT_VID
        self.topology.tx_l2_ac_port_reg.hld_obj.set_egress_vlan_edit_command(eve)

        self.setup_ingress_egress_counters()

        U.run_and_compare(
            self,
            self.device,
            self.INPUT_PACKET,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.EXPECTED_OUTPUT_PACKET_WITH_VLAN_VLAN,
            T.TX_SLICE_REG,
            T.TX_IFG_REG,
            self.l3_port_impl.serdes_reg)

        if (self.l3_port_impl.is_svi):
            packet_count, byte_count = self.l2_ingress_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            packet_count, byte_count = self.l2_egress_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_WITH_VLAN, byte_count)

        packet_count, byte_count = self.l3_ingress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.l3_egress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET_WITH_VLAN_VLAN, byte_count)

        # Remove the tag
        tag = sdk.la_vlan_tag_t()
        tag.tpid = 0
        tag.tci.fields.pcp = 0
        tag.tci.fields.dei = 0
        tag.tci.fields.vid = 0
        self.l3_port_impl.tx_port.hld_obj.set_egress_vlan_tag(tag, sdk.LA_VLAN_TAG_UNTAGGED)

        eve = sdk.la_vlan_edit_command()
        eve.num_tags_to_push = 0
        eve.num_tags_to_pop = 0
        eve.tag0.tpid = Ethertype.Dot1Q.value
        eve.tag0.tci.fields.vid = 0
        self.topology.tx_l2_ac_port_reg.hld_obj.set_egress_vlan_edit_command(eve)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if (self.l3_port_impl.is_svi):
            packet_count, byte_count = self.l2_ingress_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            packet_count, byte_count = self.l2_egress_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)

        packet_count, byte_count = self.l3_ingress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        packet_count, byte_count = self.l3_egress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET, byte_count)

        self.ip_impl.delete_route(self.topology.vrf, prefix)

    def __setup_sflow(self, snoop_packet, is_ingress, is_host, is_pci):
        # Setup punt and trap
        if is_pci:
            self.pi_port = self.topology.inject_ports[PUNT_SLICE]
            punt_ifg = 0
            punt_pif_first = self.device.get_pci_serdes()
            punt_pif_last = self.device.get_pci_serdes()
        else:
            self.pi_port = T.punt_inject_port(
                self,
                self.device,
                PUNT_SLICE,
                PUNT_IFG,
                PUNT_SP_GID,
                PUNT_PIF_FIRST,
                PUNT_INJECT_PORT_MAC_ADDR)
            punt_ifg = PUNT_IFG
            punt_pif_first = PUNT_PIF_FIRST
            punt_pif_last = PUNT_PIF_LAST

        sampling_rate = 0.5
        self.mirror_cmd = T.create_l2_mirror_command(
            self.device,
            MIRROR_CMD_INGRESS_GID,
            self.pi_port,
            HOST_MAC_ADDR,
            MIRROR_VLAN,
            sampling_rate)
        priority = 0

        # Clear trap and set snoop -> packet will go out and another packet with punt header will be generated.
        la_event = sdk.LA_EVENT_L3_INGRESS_MONITOR if is_ingress else sdk.LA_EVENT_L3_EGRESS_MONITOR
        self.orig_trap_config = self.device.get_trap_configuration(la_event)
        self.device.clear_trap_configuration(la_event)
        self._try_set_snoop(la_event, priority, self.mirror_cmd)

        # Enable netflow at input port
        if is_ingress:
            self.l3_port_impl.rx_port.hld_obj.set_ingress_sflow_enabled(True)
        else:
            self.l3_port_impl.tx_port.hld_obj.set_egress_sflow_enabled(True)

        # Set the route
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        if is_host:
            self.ip_impl.add_subnet(self.l3_port_impl.tx_port, prefix)
            self.ip_impl.add_host(self.l3_port_impl.tx_port, self.DIP, self.l3_port_impl.reg_nh.mac_addr)
        else:
            self.ip_impl.add_route(self.topology.vrf, prefix,
                                   self.l3_port_impl.reg_fec,
                                   ip_routing_base.PRIVATE_DATA)

        # Inject the packet and test outputs
        self.ingress_packet = {'data': self.INPUT_PACKET, 'slice': T.RX_SLICE, 'ifg': T.RX_IFG, 'pif': T.FIRST_SERDES}
        self.expected_packets = []
        self.expected_packets.append({'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                      'ifg': T.TX_IFG_REG, 'pif': self.l3_port_impl.serdes_reg})
        self.expected_packets.append({'data': snoop_packet, 'slice': PUNT_SLICE, 'ifg': punt_ifg, 'pif': punt_pif_first})
        self.expected_packets_no_sflow = [{'data': self.EXPECTED_OUTPUT_PACKET, 'slice': T.TX_SLICE_REG,
                                           'ifg': T.TX_IFG_REG, 'pif': self.l3_port_impl.serdes_reg}]

    def __cleanup_sflow(self, is_host, is_ingress, is_pci):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        if is_host:
            self.ip_impl.delete_host(self.l3_port_impl.tx_port, self.DIP)
            self.ip_impl.delete_subnet(self.l3_port_impl.tx_port, prefix)
        else:
            self.ip_impl.delete_route(self.topology.vrf, prefix)

        la_event = sdk.LA_EVENT_L3_INGRESS_MONITOR if is_ingress else sdk.LA_EVENT_L3_EGRESS_MONITOR
        self.device.clear_snoop_configuration(la_event)
        self.device.set_trap_configuration(la_event,
                                           self.orig_trap_config[0],  # priority
                                           self.orig_trap_config[1],  # counter_or_meter
                                           self.orig_trap_config[2],  # destination
                                           self.orig_trap_config[3],  # skip_inject_up_packets
                                           self.orig_trap_config[4],  # skip_p2p_packets
                                           self.orig_trap_config[5],  # overwrite_phb
                                           self.orig_trap_config[6])  # tc

        self.device.destroy(self.mirror_cmd)
        if not is_pci:
            self.device.destroy(self.pi_port.hld_obj)

    def __test_sflow(self, packets_nr, sampling_rate):
        self.mirror_cmd.set_probability(sampling_rate)

        mirrors = 0
        for i in range(packets_nr):
            try:
                run_and_compare_list(self, self.device, self.ingress_packet, self.expected_packets)
            except AssertionError:
                pass
            else:
                mirrors += 1

        print('packets_nr=%d mirrors=%d' % (packets_nr, mirrors))
        tolerance = 0.5
        self.assertTrue((mirrors > packets_nr * sampling_rate * (1 - tolerance)) and
                        (mirrors < packets_nr * sampling_rate * (1 + tolerance)))

        registered_sampling_rate = self.mirror_cmd.get_probability()
        self.assertAlmostEqual(sampling_rate, registered_sampling_rate)

    def _test_sflow(self, snoop_packet, is_ingress, is_host=False, is_pci=False):
        self.__setup_sflow(snoop_packet, is_ingress, is_host, is_pci)

        self.__test_sflow(packets_nr=100, sampling_rate=0.5)
        self.__test_sflow(packets_nr=500, sampling_rate=0.1)

        self.__cleanup_sflow(is_host, is_ingress, is_pci)

    def _test_sflow_add_remove_add(self, snoop_packet, is_ingress, is_host=False):
        self.__setup_sflow(snoop_packet, is_ingress, is_host, is_pci=False)
        self.__test_sflow(packets_nr=1, sampling_rate=1.0)

        # Disable sflow
        if is_ingress:
            self.l3_port_impl.rx_port.hld_obj.set_ingress_sflow_enabled(False)
        else:
            self.l3_port_impl.tx_port.hld_obj.set_egress_sflow_enabled(False)

        run_and_compare_list(self, self.device, self.ingress_packet, self.expected_packets_no_sflow)

        # Re-enable sflow
        if is_ingress:
            self.l3_port_impl.rx_port.hld_obj.set_ingress_sflow_enabled(True)
        else:
            self.l3_port_impl.tx_port.hld_obj.set_egress_sflow_enabled(True)

        self.__test_sflow(packets_nr=1, sampling_rate=1.0)

        self.__cleanup_sflow(is_host, is_ingress, is_pci=False)

    def _test_l3_ac_px_vx(self):
        px_vx_l3_ac = T.l3_ac_port(self,
                                   self.device,
                                   self.PORT_PxVx_GID,
                                   self.topology.rx_eth_port,
                                   self.topology.vrf,
                                   self.PORT_PxVx_MAC,
                                   self.PORT_PxVx_VID1)
        px_vx_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, ip_routing_base.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_PxVx, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)
        U.run_and_drop

    def _test_l3_ac_px(self):
        px_l3_ac = T.l3_ac_port(self,
                                self.device,
                                self.PORT_Px_GID,
                                self.topology.rx_eth_port,
                                self.topology.vrf,
                                self.PORT_Px_MAC)
        px_l3_ac.hld_obj.set_protocol_enabled(sdk.la_l3_protocol_e_IPV4_UC, True)

        prefix = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_fec, ip_routing_base.PRIVATE_DATA)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_Px, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

    def _test_move_host(self):
        subnet = self.ip_impl.build_prefix(self.DIP, length=16)
        self.ip_impl.add_subnet(self.l3_port_impl.tx_port, subnet)
        self.ip_impl.add_host(self.l3_port_impl.tx_port, self.DIP, self.l3_port_impl.reg_nh.mac_addr)

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        # Assume, self.l3_port_impl.reg_nh.mac_addr mac learning notification received on T.tx_l2_ac_port_def.
        #
        # Using mac aging time never for convenience. Ideally static mac entries don't move.
        # Application should consider it while handling mac move.
        tx_switch = T.topology.tx_switch(self)
        tx_l2_ac_port_def = T.topology.tx_l2_ac_port_def(self)
        # Replace L2_destination for self.l3_port_impl.reg_nh.mac_add
        tx_switch.hld_obj.set_mac_entry(
            self.l3_port_impl.reg_nh.mac_addr.hld_obj,
            tx_l2_ac_port_def.hld_obj,
            sdk.LA_MAC_AGING_TIME_NEVER)
        # test if routing works after host move
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, self.l3_port_impl.serdes_def)

        self.ip_impl.delete_host(self.l3_port_impl.tx_port, self.DIP)
        self.ip_impl.delete_subnet(self.l3_port_impl.tx_port, subnet)

    def _test_move_route_single_nh(self):
        prefix = self.ip_impl.build_prefix(self.DIP, length=16)

        self.ip_impl.add_route(self.topology.vrf, prefix, self.l3_port_impl.reg_nh, ip_routing_base.PRIVATE_DATA)

        self.setup_ingress_egress_counters()

        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_REG, T.TX_IFG_REG, self.l3_port_impl.serdes_reg)

        if (self.l3_port_impl.is_svi):
            packet_count, byte_count = self.l2_ingress_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            packet_count, byte_count = self.l2_egress_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET, byte_count)

        packet_count, byte_count = self.l3_egress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET, byte_count)

        # Assume, self.l3_port_impl.reg_nh.mac_addr mac learning notification received on T.tx_l2_ac_port_def.
        #
        # Using mac aging time never for convenience. Ideally static mac entries don't move.
        # Application should consider it while handling mac move.
        tx_switch = T.topology.tx_switch(self)
        tx_l2_ac_port_def = T.topology.tx_l2_ac_port_def(self)

        self.l2_def_egress_counter = self.device.create_counter(1)
        self.topology.tx_l2_ac_port_def.hld_obj.set_egress_counter(sdk.la_counter_set.type_e_PORT, self.l2_def_egress_counter)

        # Replace L2_destination for self.l3_port_impl.reg_nh.mac_add
        tx_switch.hld_obj.set_mac_entry(
            self.l3_port_impl.reg_nh.mac_addr.hld_obj,
            tx_l2_ac_port_def.hld_obj,
            sdk.LA_MAC_AGING_TIME_NEVER)
        # test if routing works after host move
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, self.l3_port_impl.serdes_def)

        if(self.l3_port_impl.is_svi):
            packet_count, byte_count = self.l2_ingress_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            packet_count, byte_count = self.l2_egress_counter.read(0, True, True)
            self.assertEqual(packet_count, 0)
            packet_count, byte_count = self.l2_def_egress_counter.read(0, True, True)
            self.assertEqual(packet_count, 1)
            U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET, byte_count)

        packet_count, byte_count = self.l3_egress_counter.read(0, True, True)
        self.assertEqual(packet_count, 1)
        U.assertPacketLengthEgress(self, self.EXPECTED_OUTPUT_PACKET, byte_count)
        self.ip_impl.delete_route(self.topology.vrf, prefix)

    def _test_fhrp_macs(self):
        fhrp_macs = [T.RX_HSRP_V1_IPV4_VMAC1.hld_obj,
                     T.RX_HSRP_V1_IPV4_VMAC2.hld_obj,
                     T.RX_HSRP_V2_IPV4_VMAC1.hld_obj,
                     T.RX_HSRP_V2_IPV4_VMAC2.hld_obj,
                     T.RX_HSRP_V2_IPV6_VMAC1.hld_obj,
                     T.RX_HSRP_V2_IPV6_VMAC2.hld_obj,
                     T.RX_VRRP_IPV4_VMAC1.hld_obj,
                     T.RX_VRRP_IPV4_VMAC2.hld_obj,
                     T.RX_VRRP_IPV6_VMAC1.hld_obj,
                     T.RX_VRRP_IPV6_VMAC2.hld_obj]

        # Add HSRP/VRRP MACs in NPL HW tables.
        for idx in range(len(fhrp_macs)):
            self.l3_port_impl.rx_port.hld_obj.add_virtual_mac(fhrp_macs[idx])

        # Check the number of installed entries in HW
        out_mac_addr_vec = self.l3_port_impl.rx_port.hld_obj.get_virtual_macs()
        self.assertEqual(len(fhrp_macs), len(out_mac_addr_vec))

        # Compare the entries
        for idx in range(len(out_mac_addr_vec)):
            self.assertEqual(fhrp_macs[idx].flat, out_mac_addr_vec[idx].flat)

        # Remove entries from HW
        for idx in range(len(fhrp_macs)):
            self.l3_port_impl.rx_port.hld_obj.remove_virtual_mac(fhrp_macs[idx])

        # Verify the removal of entries from HW
        out_mac_addr_vec = self.l3_port_impl.rx_port.hld_obj.get_virtual_macs()
        self.assertEqual(len(out_mac_addr_vec), 0)

    def _test_route_hsrp_v1_ipv4_vmac(self):
        self.l3_port_impl.rx_port.hld_obj.add_virtual_mac(T.RX_HSRP_V1_IPV4_VMAC1.hld_obj)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_HSRP_V1_IPV4_VMAC, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, self.l3_port_impl.serdes_def)

        self.l3_port_impl.rx_port.hld_obj.remove_virtual_mac(T.RX_HSRP_V1_IPV4_VMAC1.hld_obj)
        U.run_and_drop(self, self.device, self.INPUT_PACKET_HSRP_V1_IPV4_VMAC, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def _test_route_hsrp_v2_ipv4_vmac(self):
        self.l3_port_impl.rx_port.hld_obj.add_virtual_mac(T.RX_HSRP_V2_IPV4_VMAC1.hld_obj)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_HSRP_V2_IPV4_VMAC, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, self.l3_port_impl.serdes_def)

        self.l3_port_impl.rx_port.hld_obj.remove_virtual_mac(T.RX_HSRP_V2_IPV4_VMAC1.hld_obj)
        U.run_and_drop(self, self.device, self.INPUT_PACKET_HSRP_V2_IPV4_VMAC, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def _test_route_vrrp_ipv4_vmac(self):
        self.l3_port_impl.rx_port.hld_obj.add_virtual_mac(T.RX_VRRP_IPV4_VMAC1.hld_obj)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_VRRP_IPV4_VMAC, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, self.l3_port_impl.serdes_def)

        self.l3_port_impl.rx_port.hld_obj.remove_virtual_mac(T.RX_VRRP_IPV4_VMAC1.hld_obj)
        U.run_and_drop(self, self.device, self.INPUT_PACKET_VRRP_IPV4_VMAC, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def _test_route_hsrp_v2_ipv6_vmac(self):
        self.l3_port_impl.rx_port.hld_obj.add_virtual_mac(T.RX_HSRP_V2_IPV6_VMAC1.hld_obj)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_HSRP_V2_IPV6_VMAC, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, self.l3_port_impl.serdes_def)

        self.l3_port_impl.rx_port.hld_obj.remove_virtual_mac(T.RX_HSRP_V2_IPV6_VMAC1.hld_obj)
        U.run_and_drop(self, self.device, self.INPUT_PACKET_HSRP_V2_IPV6_VMAC, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)

    def _test_route_vrrp_ipv6_vmac(self):
        self.l3_port_impl.rx_port.hld_obj.add_virtual_mac(T.RX_VRRP_IPV6_VMAC1.hld_obj)
        U.run_and_compare(self, self.device,
                          self.INPUT_PACKET_VRRP_IPV6_VMAC, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES,
                          self.EXPECTED_DEFAULT_OUTPUT_PACKET, T.TX_SLICE_DEF, T.TX_IFG_DEF, self.l3_port_impl.serdes_def)

        self.l3_port_impl.rx_port.hld_obj.remove_virtual_mac(T.RX_VRRP_IPV6_VMAC1.hld_obj)
        U.run_and_drop(self, self.device, self.INPUT_PACKET_VRRP_IPV6_VMAC, T.RX_SLICE, T.RX_IFG, T.FIRST_SERDES)
