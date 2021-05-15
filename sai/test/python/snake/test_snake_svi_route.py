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

import pytest
from saicli import *
import time
import sai_topology as topology
import unittest
import sai_packet_utils as pkt_utils
import sai_test_utils as st_utils
import sai_test_base as st_base
from scapy.all import *


class sai_snake_svi_route(unittest.TestCase):
    PORT_CFG_FILE = None

    def test_all_bgp_punt(self):
        self.trap_group = self.tb.create_trap_group(7)
        self.bgp_trap = self.tb.create_trap(SAI_HOSTIF_TRAP_TYPE_BGP, SAI_PACKET_ACTION_TRAP, 251, self.trap_group)

        for (idx, port) in iter(enumerate(self.top.snake_port_list)):
            (svi_mac, neighbor_mac) = self.top.get_svi_neighbor_mac(idx)
            in_pkt = Ether(dst=svi_mac, src=self.top.neighbor_mac1) / \
                Dot1Q(vlan=self.top.snake_base_vlan + 2 * idx) / \
                IP(src=self.top.neighbor_ip1, dst=self.top.local_ip1, proto=6, ttl=64) / \
                TCP(sport=179, dport=50)
            in_pkt = in_pkt / ("\0" * 20)

            pkt_utils.punt_test(self, in_pkt, port, in_pkt, 1, self.bgp_trap)

        if self.tb.debug_log:
            st_utils.print_ports_stats(self.tb)
            attr = sai_attribute_t(SAI_SWITCH_ATTR_CPU_PORT, 0)
            self.tb.apis[SAI_API_SWITCH].get_switch_attribute(self.tb.switch_id, 1, attr)
            st_utils.print_port_queue_stats(self.tb, attr.value.oid)

    def test_all_arp_punt(self):
        self.tb.log("---- punt all arp --------------------------------")
        for (idx, port) in iter(enumerate(self.top.snake_port_list)):
            in_pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.top.neighbor_mac1) / \
                Dot1Q(vlan=self.top.snake_base_vlan + 2 * idx) / ARP() / ("\0" * 20)

            pkt_utils.punt_test(self, in_pkt, port)

        if self.tb.debug_log:
            st_utils.print_ports_stats(self.tb)
            attr = sai_attribute_t(SAI_SWITCH_ATTR_CPU_PORT, 0)
            self.tb.apis[SAI_API_SWITCH].get_switch_attribute(self.tb.switch_id, 1, attr)
            st_utils.print_port_queue_stats(self.tb, attr.value.oid)

    def test_all_cpu_punt(self):
        self.tb.log("---- punt all to cpu --------------------------------")
        for (idx, port) in iter(enumerate(self.top.snake_port_list)):
            (svi_mac, neighbor_mac) = self.top.get_svi_neighbor_mac(idx)
            in_pkt = Ether(dst=svi_mac, src=self.top.neighbor_mac1) / \
                Dot1Q(vlan=self.top.snake_base_vlan + 2 * idx) / \
                IP(src=self.top.neighbor_ip1, dst=self.top.local_ip1, ttl=64) / \
                UDP(sport=64, dport=2048)

            pkt_utils.punt_test(self, in_pkt, port)

        if self.tb.debug_log:
            st_utils.print_ports_stats(self.tb)

    def test_snake_svi_route(self):
        # verified on blacktip with spirent using interactive mode.

        total_ports = len(self.top.snake_port_list)

        in_pkt = Ether(dst=self.top.svi_mac1, src=self.top.svi_mac2) / \
            Dot1Q(vlan=self.top.snake_base_vlan) / \
            IP(src=self.top.neighbor_ip1, dst=self.top.svi_router_ip, ttl=64) / \
            UDP(sport=64, dport=2048)

        out_pkt = Ether(dst=self.top.svi_mac1, src=self.top.svi_mac2) / \
            Dot1Q(vlan=self.top.snake_base_vlan) / \
            IP(src=self.top.neighbor_ip1, dst=self.top.svi_router_ip, ttl=64 - total_ports) / \
            UDP(sport=64, dport=2048)

        self.tb.log("Sending traffic now...")
        pkt_utils.run_and_compare(self, in_pkt, self.top.tg_port, out_pkt, self.top.tg_port)

        self.tb.log("------------------------------------")
        self.tb.log("Print all port stats...")
        if self.tb.debug_log:
            st_utils.print_ports_stats(self.tb)
            st_utils.print_port_queue_stats(self.tb, self.tb.ports[self.top.tg_port])

    @classmethod
    def set_port_cfg_file(cls, file_name):
        cls.PORT_CFG_FILE = file_name

    @classmethod
    def setUpClass(cls):
        pytest.tb = cls.tb = st_base.sai_test_base()
        cls.tb.setUp()
        cls.top = topology.sai_topology(cls.tb, "v4")

        if cls.PORT_CFG_FILE is None:
            SDK_ROOT = os.getenv('SDK_ROOT', os.getcwd() + "/../")
            port_config_pathname = SDK_ROOT + "/sai/test/python/"
            if cls.tb.is_gb:
                cls.PORT_CFG_FILE = port_config_pathname + "snake/sai_snake_port_cfg_gb.json"
            else:
                cls.PORT_CFG_FILE = port_config_pathname + "snake/sai_snake_port_cfg.json"

        ports_config = st_utils.load_ports_from_json(cls.PORT_CFG_FILE)
        if cls.tb.debug_log:
            st_utils.print_ports_config(ports_config)
        cls.top.configure_svi_route_snake_topology(ports_config)
        cls.top.configure_bridge_ports_learning_mode(SAI_BRIDGE_PORT_FDB_LEARNING_MODE_DISABLE)
        cls.tb.set_all_ports_admin_state(True)
        time.sleep(5)
        st_utils.list_active_ports(cls.tb, None, cls.tb.debug_log)

    @classmethod
    def tearDownClass(cls):
        cls.tb.tearDown()


if __name__ == '__main__':
    unittest.main()

    # For interactive debug / HW testing using Pangea
    '''
    tc = sai_snake_svi_route()
    st_utils.update_config_file("config/pershing_p3.json")
    tc.set_port_cfg_file("test/python/snake/pershing_port_cfg.json")
    tc.setUp()

    st_utils.list_active_ports(tc.tb)
    '''
