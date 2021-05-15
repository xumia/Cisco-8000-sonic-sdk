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
import argparse
import sys

import basic_access

device_id = 1
devpath = None

# turn on {LLD,SIM}:DEBUG prints for device_id==1 and for 'unknown device'


def debug_on():
    from leaba import sdk as sdk
    lld_components = [
        sdk.la_logger_component_e_SIM,
        sdk.la_logger_component_e_LLD,
        sdk.la_logger_component_e_ACCESS,
        sdk.la_logger_component_e_SBIF]
    for dev_id in [device_id, 288]:
        for component in lld_components:
            sdk.la_set_logging_level(self.device_id, component, sdk.la_logger_level_e_DEBUG)


class rtl_access_unit_test(basic_access.basic_access_base):

    # Invoked once per class instance, a good place for expensive initializations
    # cls.ll_device and friends are accessible as self.ll_device
    @classmethod
    def setUpClass(cls):
        # TODO: Launch fullchip RTL and automatically discover port_rw & port_int

        debug_on()

        global devpath

        cls.simulator = test_lldcli.create_socket_simulator(devpath)
        assert cls.simulator is not None, "create_socket_simulator failed"

        cls.ll_device = lldcli.ll_device_create(device_id, '/dev/testdev')
        assert cls.ll_device is not None, "ll_device_create failed"
        cls.ll_device.set_device_simulator(cls.simulator, lldcli.ll_device.simulation_mode_e_SBIF)

        # By default, we want to work with access engine in Fifo mode, but this can be disabled.
        # If Fifo is disabled, the SDK handles Fifo pointers manually (part of the contract with the HW).
        # cls.ll_device.set_access_engine_cmd_fifo_enable(False)

        cls.lbr_tree = cls.ll_device.get_pacific_tree()

        # Clean start - reset the access engines. For this test we do not need any deeper resets.
        cls.ll_device.reset_access_engines(0xff)

    # Invoked once per class instance
    @classmethod
    def tearDownClass(cls):
        pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='localhost', required=True, help='server hostname')
    parser.add_argument('--port_rw', type=int, default=0, required=True, help='TCP port for read/write')
    parser.add_argument('--port_int', type=int, default=0, required=True, help='TCP port for interrupt')
    parser.add_argument('unittest_args', nargs='*')

    args, unknown_args = parser.parse_known_args()

    devpath = '/dev/testdev/socket?host={0}&port_rw={1}&port_int={2}'.format(args.host, args.port_rw, args.port_int)

    # unknown_args captures args with dashes ('-v')
    # args.unittest_args captures args without dashes ('TestA')
    sys.argv[1:] = unknown_args + args.unittest_args
    unittest.main()
