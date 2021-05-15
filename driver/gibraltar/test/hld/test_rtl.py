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
import lldcli
import test_lldcli
import hld_sim_utils
from leaba import sdk


class test_rtl(unittest.TestCase):

    def setUp(self):
        port_rw = 0
        port_int = 0
        # create device side (e.g. RTL)
        self.socket_device = test_lldcli.socket_device_create(port_rw, port_int)
        self.assertNotEqual(self.socket_device, None)
        port_rw = self.socket_device.get_port_rw()
        port_int = self.socket_device.get_port_int()
        device_path = "/dev/testdev/socket?host=localhost&port_rw={0}&port_int={1}".format(port_rw, port_int)
        device_id = 0
        # create SDK side (host side)
        self.device = hld_sim_utils.create_rtl_device(device_path, device_id)
        self.ll_device = self.device.get_ll_device()
        self.lbr_tree = self.ll_device.get_pacific_tree()

    def tearDown(self):
        # Device has an open "client" connection with socket_device which is a "server".
        # First, take the "client" down, then the "server".
        self.device.tearDown()
        self.socket_device = None

    def test_register_access(self):
        value_to_write = 0x2d
        reg = self.lbr_tree.sbif.misc_output_reg
        self.ll_device.write_register(reg, value_to_write)
        value = self.ll_device.read_register(reg)
        self.assertEqual(value, value_to_write)


if __name__ == '__main__':
    unittest.main()
