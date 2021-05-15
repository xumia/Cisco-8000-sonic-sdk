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
import topology as T

import mac_port_board_test_base as board_base

SYS_PORT_GID_BASE = 23
AC_PORT_GID_BASE = 10

DST_MAC = "ca:fe:ca:fe:ca:fe"
SRC_MAC = "de:ad:de:ad:de:ad"
VLAN = 0xAB9


class l2_p2p_xconnect_unit_test(board_base.mac_port_board_test_base):

    def setUp(self):
        self.device_init(True)
        self.topology = T.topology(self, self.device, create_default_topology=False)

    def tearDown(self):
        #status = sdk.la_destroy_device(self.device)
        status = sdk.la_status_e_SUCCESS
        self.assertEqual(status, sdk.la_status_e_SUCCESS)

    def xena_test(self, mac_port_configs):
        self.cur_slice = 2
        self.cur_ifg = 0
        self.cur_serdes = 0

        self.create_mac_ports(mac_port_configs)

        # Activate
        for mac_port in self.mac_ports:
            try:
                mac_port.activate()
            except sdk.BaseException:
                raise Exception('activate slice {}, IFG {}, SerDes {}'.format(
                    mac_port.get_slice(), mac_port.get_ifg(), mac_port.get_first_serdes_id()))

            try:
                mac_port.tune(True)
            except sdk.BaseException:
                raise Exception('tune slice {}, IFG {}, SerDes {}'.format(
                    mac_port.get_slice(), mac_port.get_ifg(), mac_port.get_first_serdes_id()))

        self.retune()
        self.check_mac_up()

    def l2_xconnect_setup(self):
        mac_port_configs = []
        mac_port_configs.append({'name': "2x25G", 'serdes_count': 2, 'speed': sdk.la_mac_port.port_speed_e_E_50G,
                                 'fec_modes': [
                                     sdk.la_mac_port.fec_mode_e_RS_KR4],
                                 'fc_modes': [
                                     sdk.la_mac_port.fc_mode_e_NONE,
                                     sdk.la_mac_port.fc_mode_e_NONE]
                                 })

        self.xena_test(mac_port_configs)

        self.ac_profile = T.ac_profile(self, self.device)

        self.eth_port1 = T.ethernet_port(self, self.device, -1, -1, SYS_PORT_GID_BASE, -1, -1, None, self.mac_ports[0])
        self.eth_port1.set_ac_profile(self.ac_profile)
        self.ac_port1 = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE, None, self.eth_port1, None, VLAN, 0x0)

    def test_l2_p2p_xconnect(self):
        self.l2_xconnect_setup()

        self.eth_port2 = T.ethernet_port(self, self.device, -1, -1, SYS_PORT_GID_BASE + 1, -1, -1, None, self.mac_ports[1])
        self.eth_port2.set_ac_profile(self.ac_profile)
        self.ac_port2 = T.l2_ac_port(self, self.device, AC_PORT_GID_BASE + 1, None, self.eth_port2, None, VLAN, 0x0)

        self.ac_port1.hld_obj.set_destination(self.ac_port2.hld_obj)
        self.ac_port2.hld_obj.set_destination(self.ac_port1.hld_obj)

    def test_l2_p2p_loopback(self):
        self.l2_xconnect_setup()

        # Pass packet from port 1 to itself
        self.ac_port1.hld_obj.set_destination(self.ac_port1.hld_obj)


if __name__ == '__main__':
    unittest.main()
