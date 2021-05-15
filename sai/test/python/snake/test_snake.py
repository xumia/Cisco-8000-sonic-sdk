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


class sai_snake(unittest.TestCase):
    PORT_CFG_FILE = None

    def test_snake(self):
        st_utils.list_active_ports(self.tb, None, self.tb.debug_log)

        pkt = Ether(dst="00:07:07:07:07:07", src="00:ef:00:ef:00:ef") / \
            Dot1Q(vlan=self.top.snake_base_vlan) / \
            IP(src=self.top.neighbor_ip1, dst=self.top.neighbor_ip2, ttl=64) / \
            UDP(sport=64, dport=2048)

        self.tb.log("Sending traffic now...")
        pkt_utils.run_and_compare(self, pkt, self.top.tg_port, pkt, self.top.tg_port)

        self.tb.log("------------------------------------")
        self.tb.log("Print all port stats...")
        if self.tb.debug_log:
            st_utils.print_ports_stats(self.tb)

    @classmethod
    def set_port_cfg_file(cls, file_name):
        cls.PORT_CFG_FILE = file_name

    @classmethod
    def setUp(cls, board_type=None):
        pytest.tb = cls.tb = st_base.sai_test_base()
        cls.tb.setUp(board_type=board_type)
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

        cls.top.configure_dot1q_bridge_snake_topology(ports_config, create_ports=True)
        cls.tb.set_all_ports_admin_state(True)
        time.sleep(5)

    @classmethod
    def tearDown(cls):
        cls.tb.tearDown()


if __name__ == '__main__':
    unittest.main()

    # For interactive debug / HW testing using Pangea
    '''
    tc = sai_snake()
    tc.set_port_cfg_file("test/python/snake/pershing_port_cfg.json")
    tc.setUp()

    st_utils.list_active_ports(tc.tb)
    '''
