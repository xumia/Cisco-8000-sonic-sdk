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

import unittest
import lldcli
import test_lldcli
import basic_access
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_gibraltar(), "Disabled on GB, tests are using Pacific tree")
class basic_access_unit_test(basic_access.basic_access_base):

    # Invoked once per class instance, a good place for expensive initializations
    # cls.ll_device and friends are accessible as self.ll_device
    @classmethod
    def setUpClass(cls):
        port_rw = 0
        port_int = 0
        cls.socket_device = test_lldcli.socket_device_create(port_rw, port_int)
        assert cls.socket_device is not None, "socket_device_create failed"

        port_rw = cls.socket_device.get_port_rw()
        port_int = cls.socket_device.get_port_int()
        device_path = "/dev/testdev/socket?host=localhost&port_rw=%d&port_int=%d" % (port_rw, port_int)
        cls.simulator = test_lldcli.create_socket_simulator(device_path)
        assert cls.simulator is not None, "create_socket_simulator failed"

        device_id = 0
        cls.ll_device = lldcli.ll_device_create(device_id, device_path)
        assert cls.ll_device is not None, "ll_device_create failed"
        cls.ll_device.set_device_simulator(cls.simulator, lldcli.ll_device.simulation_mode_e_LBR)
        cls.lbr_tree = cls.ll_device.get_pacific_tree()

    # Invoked once per class instance
    @classmethod
    def tearDownClass(cls):
        # Device has an open "client" connection with socket_device which is a "server".
        # First, take the "client" down, then the "server".
        cls.ll_device = None
        cls.socket_device = None


if __name__ == '__main__':
    unittest.main()
