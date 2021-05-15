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

import unittest
from leaba import sdk
import sim_utils
import topology as T
from packet_test_utils import *
from scapy.all import *
from sdk_test_case_base import sdk_test_case_base


class l2_protection_group_base(sdk_test_case_base):

    l2_protection_group_gid = 0x500

    def setUp(self):
        super().setUp(create_default_topology=False)

        # MATILDA_SAVE -- need review
        self.s_rx_slice = T.choose_active_slices(self.device, self.s_rx_slice, [5, 1])
        self.s_tx_prim_slice = T.choose_active_slices(self.device, self.s_tx_prim_slice, [2, 3])
        self.s_tx_spa_slice = T.choose_active_slices(self.device, self.s_tx_spa_slice, [4, 0])
        if self.s_tx_spa_slice == self.s_tx_prim_slice:
            self.s_tx_spa_ifg = 0

        self.topology.create_inject_ports()
        self._add_objects_to_keep()

    # create network topology
    #
    #  RX -------> | ----------->  TX
    #              |
    #              |                  primary (over sp)----transmit
    #              |                 /
    #  receive--switch--l2_protection
    #              |                 \
    #              |                  protecting (over spa)----transmit
    #              |
    def create_network_topology(self):
        self.m_switch = self.device.create_switch(0x100)
        self.assertNotEqual(self.m_switch, None)

        self.m_rx_port = self.create_ac_port_on_system_port(
            self.s_rx_slice,
            self.s_rx_ifg,
            self.s_first_serdes,
            self.s_last_serdes,
            0x11,
            0x12,
            self.s_vlan1,
            self.s_vlan2)
        self.m_rx_port.hld_obj.attach_to_switch(self.m_switch)

        self.m_tx_primary_port = self.create_ac_port_on_system_port(
            self.s_tx_prim_slice,
            self.s_tx_prim_ifg,
            self.s_first_serdes_prim,
            self.s_last_serdes_prim,
            0x21,
            0x22,
            0,
            0)
        self.m_tx_primary_port.hld_obj.attach_to_switch(self.m_switch)

        self.m_tx_protecting_port = self.create_ac_port_on_spa_port(0x41, 0x42, 0x43, 0, 0)
        self.m_tx_protecting_port.hld_obj.attach_to_switch(self.m_switch)

        self.m_protection_monitor = self.device.create_protection_monitor()
        self.assertNotEqual(self.m_protection_monitor, None)

        self.m_l2_protection_group = self.device.create_l2_protection_group(
            self.l2_protection_group_gid, self.m_tx_primary_port.hld_obj,
            self.m_tx_protecting_port.hld_obj, self.m_protection_monitor)
        self.assertNotEqual(self.m_l2_protection_group, None)

    def configure_switching(self):
        self.m_switch.set_mac_entry(
            self.s_dest_mac.hld_obj,
            self.m_l2_protection_group,
            sdk.LA_MAC_AGING_TIME_NEVER)

    # Utility functions

    def create_system_port_on_mac_port(self, slice, ifg, first_serdes, last_serdes, system_port_gid):
        _mac_port = T.mac_port(self, self.device, slice, ifg, first_serdes, last_serdes)
        _mac_port.activate()
        sys_port = T.system_port(self, self.device, system_port_gid, _mac_port)

        return sys_port

    def create_ac_port_on_sys_or_spa_port(self, sys_or_spa_port, ac_port_gid, vid1, vid2):
        eth_port = T.sa_ethernet_port(self, self.device, sys_or_spa_port)
        ac_port = T.l2_ac_port(self, self.device, ac_port_gid, self.topology.filter_group_def, None, eth_port, None, vid1, vid2)

        return ac_port

    def create_ac_port_on_system_port(
            self,
            slice,
            ifg,
            first_serdes,
            last_serdes,
            system_port_gid,
            ac_port_gid,
            vid1,
            vid2):
        sys_port = self.create_system_port_on_mac_port(slice, ifg, first_serdes, last_serdes, system_port_gid)

        ac_port = self.create_ac_port_on_sys_or_spa_port(sys_port, ac_port_gid, vid1, vid2)

        return ac_port

    def create_ac_port_on_spa_port(self, system_port_gid, spa_port_gid, ac_port_gid, vid1, vid2):
        sys_port = self.create_system_port_on_mac_port(
            self.s_tx_spa_slice,
            self.s_tx_spa_ifg,
            self.s_first_serdes_spa,
            self.s_last_serdes_spa,
            system_port_gid)

        spa_port = T.spa_port(self, self.device, spa_port_gid)
        spa_port.add(sys_port)

        ac_port = self.create_ac_port_on_sys_or_spa_port(spa_port, ac_port_gid, vid1, vid2)

        return ac_port

    # Static member
    s_first_serdes = T.get_device_out_first_serdes(0)
    s_last_serdes = T.get_device_out_last_serdes(1)
    s_first_serdes_prim = T.get_device_first_serdes(0)
    s_last_serdes_prim = T.get_device_last_serdes(1)
    s_first_serdes_spa = T.get_device_next_first_serdes(0)
    s_last_serdes_spa = T.get_device_next_last_serdes(1)
    s_rx_slice = T.get_device_slice(5)
    s_tx_prim_slice = T.get_device_slice(2)
    s_tx_spa_slice = T.get_device_slice(4)
    s_rx_ifg = 0
    s_tx_prim_ifg = T.get_device_ifg(1)
    s_tx_spa_ifg = T.get_device_ifg(1)
    s_vlan1 = 0x8a
    s_vlan2 = 0
    s_dest_mac = T.mac_addr("84:20:75:3e:8c:05")
    s_src_mac = T.mac_addr("be:ef:5d:35:7a:35")

    s_packet_base = Ether(dst=s_dest_mac.addr_str, src=s_src_mac.addr_str, type=Ethertype.Dot1Q.value) / \
        Dot1Q(vlan=s_vlan1) / \
        IP() / TCP()
    s_packet, __ = enlarge_packet_to_min_length(s_packet_base)


if __name__ == '__main__':
    unittest.main()
