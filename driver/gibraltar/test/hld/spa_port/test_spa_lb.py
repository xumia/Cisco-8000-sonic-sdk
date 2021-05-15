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

from packet_test_utils import *
from spa_port.spa_port_base import *
from scapy.all import *
import unittest
from leaba import sdk
import topology as T
from math import gcd
from leaba import hldcli
import decor


class spa_port_loadbalance(spa_port_base):

    SPA_PORT_GID = 123
    SYSTEM_PORT_GID_BASE = 100

    port_speed_to_num = {sdk.la_mac_port.port_speed_e_E_10G: 10,
                         sdk.la_mac_port.port_speed_e_E_25G: 25,
                         sdk.la_mac_port.port_speed_e_E_40G: 40,
                         sdk.la_mac_port.port_speed_e_E_50G: 50,
                         sdk.la_mac_port.port_speed_e_E_100G: 100,
                         sdk.la_mac_port.port_speed_e_E_200G: 200,
                         sdk.la_mac_port.port_speed_e_E_400G: 400,
                         sdk.la_mac_port.port_speed_e_E_800G: 800}

    def setUp(self):
        super().setUp()

        self.mac_ports_speed = [sdk.la_mac_port.port_speed_e_E_100G,
                                sdk.la_mac_port.port_speed_e_E_50G,
                                sdk.la_mac_port.port_speed_e_E_40G]

        assert(0 < len(self.mac_ports_speed) <= len(self.s_tx))

        # Configurations were taken from 'mac_pool_port.c' ->  's_valid_configurations'
        # {port_speed : [fec_mode, num_of_serdeses]}
        self.mac_port_conf_map = {sdk.la_mac_port.port_speed_e_E_40G: [sdk.la_mac_port.fec_mode_e_NONE, 2],
                                  sdk.la_mac_port.port_speed_e_E_50G: [sdk.la_mac_port.fec_mode_e_RS_KR4, 2],
                                  sdk.la_mac_port.port_speed_e_E_100G: [sdk.la_mac_port.fec_mode_e_RS_KR4, 2],
                                  sdk.la_mac_port.port_speed_e_E_400G: [sdk.la_mac_port.fec_mode_e_RS_KP4, 8]}

        self.mac_ports = []
        for i in range(len(self.mac_ports_speed)):
            mac_port_speed = self.mac_ports_speed[i]
            last_serdes = self.s_tx[i].first_serdes + self.mac_port_conf_map[mac_port_speed][1] - 1
            mac_port = T.mac_port(self,
                                  self.device,
                                  self.s_tx[i].slice,
                                  self.s_tx[i].ifg,
                                  self.s_tx[i].first_serdes,
                                  last_serdes,
                                  speed=mac_port_speed,
                                  fec_mode=self.mac_port_conf_map[mac_port_speed][0])
            self.mac_ports.append(mac_port)

        self.sys_ports = []
        for i in range(len(self.mac_ports_speed)):
            sys_port = T.system_port(self, self.device, self.SYSTEM_PORT_GID_BASE + i, self.mac_ports[i])
            self.sys_ports.append(sys_port)

        self.spa_port = T.spa_port(self, self.device, self.SPA_PORT_GID)
        for sp in self.sys_ports:
            self.spa_port.add(sp)
        self.spa_port_base = self.spa_port.hld_obj.imp()

        self.create_topology(self.spa_port)

    def create_packets(self):
        self.SRC_MAC = [self.SRC_MAC_A,
                        self.SRC_MAC_B,
                        self.SRC_MAC_C]

        self.in_packets = []
        self.out_packets = []

        for i in range(len(self.SRC_MAC)):
            packet_base = Ether(dst=self.DST_MAC, src=self.SRC_MAC[i], type=Ethertype.Dot1Q.value) / \
                Dot1Q(vlan=self.VLAN) / \
                IP() / TCP()

            in_packet, out_packet = pad_input_and_output_packets(packet_base, packet_base)
            self.in_packets.append(in_packet)
            self.out_packets.append(out_packet)

    def check_members(self):
        # Verify (by use cases) 'port_dspa_table' configuration correctness:
        # Inject packets SP-AC -> SPA-AC

        for i in range(len(self.in_packets)):
            self.run_and_compare_spa(
                self.spa_port,
                sdk.LA_LB_VECTOR_IPV4_NON_TCP_UDP,
                self.in_packets[i],
                self.IN_SLICE,
                self.IN_IFG,
                self.IN_SERDES_FIRST,
                self.out_packets[i])

    def test_spa_port_loadbalance_add(self):
        # 100|10  50|5  40|4

        res_sys_ports = self.spa_port_base.get_dspa_table_members()

        qu = self.port_speed_to_num[self.mac_ports_speed[0]]
        for mac_port_speed in self.mac_ports_speed:
            qu = gcd(qu, self.port_speed_to_num[mac_port_speed])

        # Verify system_port addition correctness
        for i in range(len(self.sys_ports)):
            sp_oid = self.sys_ports[i].hld_obj.oid()
            expected_num_of_entries = self.port_speed_to_num[self.mac_ports_speed[i]] / qu

            num_of_sp_entries = 0
            for sp in res_sys_ports:
                if sp.oid() == sp_oid:
                    num_of_sp_entries += 1

            self.assertEqual(expected_num_of_entries, num_of_sp_entries)

        self.check_members()

    def test_spa_port_loadbalance_remove(self):
        # Remove 50G system_port:
        # 100|10  50|5  40|4   -->   100|5  40|2

        sys_port_to_remove_index = self.mac_ports_speed.index(sdk.la_mac_port.port_speed_e_E_50G)
        sys_port_to_remove = self.sys_ports[sys_port_to_remove_index]
        sys_port_to_remove_oid = sys_port_to_remove.hld_obj.oid()

        self.spa_port.remove(sys_port_to_remove)

        # Recalculate qu:
        if sys_port_to_remove_index > 0:
            qu = self.port_speed_to_num[self.mac_ports_speed[0]]
        elif len(self.mac_ports_speed) > 1:
            qu = self.port_speed_to_num[self.mac_ports_speed[1]]

        for i in range(len(self.mac_ports_speed)):
            if i == sys_port_to_remove_index:
                continue
            mac_port_speed = self.mac_ports_speed[i]
            qu = gcd(qu, self.port_speed_to_num[mac_port_speed])

        res_sys_ports = self.spa_port_base.get_dspa_table_members()

        # Verify system_port removal correctness
        for i in range(len(self.sys_ports)):
            if i == sys_port_to_remove_index:
                for sp in res_sys_ports:
                    if sp.oid() == sys_port_to_remove_oid:
                        assert(False)
            else:
                sp_oid = self.sys_ports[i].hld_obj.oid()
                expected_num_of_entries = self.port_speed_to_num[self.mac_ports_speed[i]] / qu

                num_of_sp_entries = 0
                for sp in res_sys_ports:
                    if sp.oid() == sp_oid:
                        num_of_sp_entries += 1

                self.assertEqual(expected_num_of_entries, num_of_sp_entries)

        self.check_members()

    @unittest.skipIf(decor.is_matilda("3.2"), "GB 3.2 Does not support mac_port->reconfigure() functionality")
    def test_spa_port_loadbalance_speed_change(self):
        # Denotation for the following test:
        # {U} - Updated port
        # {R} - Rest of the ports
        # D - Dilution (of entries)
        # E - Extension (of entries)

        # Change 40G port speed to 50G (will trigger <{R}, {U}> = <D, D>):
        # 100|10  50|5  40|4   -->   100|2  50|1  50|1
        mac_port_to_change_index = self.mac_ports_speed.index(sdk.la_mac_port.port_speed_e_E_40G)
        self.change_speed(mac_port_to_change_index, sdk.la_mac_port.port_speed_e_E_50G)

        # Change back 50G port speed to 40G (will trigger <{R}, {U}> = <E, E>):
        # 100|2  50|1  50|1   -->   100|10  50|5  40|4
        self.change_speed(mac_port_to_change_index, sdk.la_mac_port.port_speed_e_E_40G)

        # Change 40G port speed to 400G (will trigger <{R}, {U}> = <D, E>):
        # 100|10  50|5  40|4   -->   100|2  50|1  400|8
        self.change_speed(mac_port_to_change_index, sdk.la_mac_port.port_speed_e_E_400G)

        # Change back 400G port speed to 40G (will trigger <{R}, {U}> = <E, D>):
        # 100|2  50|1  400|8   -->   100|10  50|5  40|4
        self.change_speed(mac_port_to_change_index, sdk.la_mac_port.port_speed_e_E_40G)

    def change_speed(self, mac_port_to_change_index, new_speed):
        mac_port_to_change = self.mac_ports[mac_port_to_change_index]

        mac_port_to_change.hld_obj.reconfigure(self.mac_port_conf_map[new_speed][1],
                                               new_speed,
                                               sdk.la_mac_port.fc_mode_e_NONE,
                                               sdk.la_mac_port.fc_mode_e_NONE,
                                               self.mac_port_conf_map[new_speed][0])
        self.mac_ports_speed[mac_port_to_change_index] = new_speed

        qu = self.port_speed_to_num[self.mac_ports_speed[0]]
        for mac_port_speed in self.mac_ports_speed:
            qu = gcd(qu, self.port_speed_to_num[mac_port_speed])

        # Verify correct num of entries for each system_port
        res_sys_ports = self.spa_port_base.get_dspa_table_members()

        for i in range(len(self.sys_ports)):
            expected_num_of_entries = self.port_speed_to_num[self.mac_ports_speed[i]] / qu
            sp_oid = self.sys_ports[i].hld_obj.oid()
            num_of_sp_entries = 0
            for sp in res_sys_ports:
                if sp.oid() == sp_oid:
                    num_of_sp_entries += 1

            self.assertEqual(expected_num_of_entries, num_of_sp_entries)

        self.check_members()


if __name__ == '__main__':
    unittest.main()
