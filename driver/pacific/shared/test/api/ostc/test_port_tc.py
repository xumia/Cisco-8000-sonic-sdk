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
import os
import unittest
from leaba import sdk
import sim_utils

from sdk_test_case_base import *

MAC_PORT1_SLICE = T.get_device_slice(1)
MAC_PORT1_IFG = T.get_device_ifg(1)


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_port_tc(sdk_test_case_base):

    def setUp(self):
        super().setUp(create_default_topology=False)
        mac_port0_params = [0, 0, 0, 1, sdk.la_mac_port.port_speed_e_E_50G,
                            sdk.la_mac_port.fc_mode_e_NONE, sdk.la_mac_port.fec_mode_e_NONE]
        mac_port1_params = [MAC_PORT1_SLICE, MAC_PORT1_IFG, 8, 11, sdk.la_mac_port.port_speed_e_E_100G,
                            sdk.la_mac_port.fc_mode_e_NONE, sdk.la_mac_port.fec_mode_e_NONE]
        self.mac_ports = []
        for mac_port_params in [mac_port0_params, mac_port1_params]:
            slice_id, ifg_id, serdes_start, serdes_last, speed, fc_mode, fec_mode = mac_port_params
            mac_port = self.device.create_mac_port(slice_id, ifg_id, serdes_start, serdes_last, speed, fc_mode, fec_mode)
            self.mac_ports.append(mac_port)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_default_port_tc(self):
        for mac_port in self.mac_ports:
            for ostc in range(3):
                for itc in range(8):
                    mac_port.set_default_port_tc(ostc, itc)
                    res_default_ostc, res_default_itc = mac_port.get_default_port_tc()
                    self.assertEqual(res_default_ostc, ostc)
                    self.assertEqual(res_default_itc, itc)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_port_tc_custom_protocols(self):
        for mac_port in self.mac_ports:
            protocols = [0x1000, 0x2000]
            for protocol in protocols:
                mac_port.add_port_tc_custom_protocol(protocol)

            res_protocols = sorted(mac_port.get_port_tc_custom_protocols())
            self.assertEqual(res_protocols, protocols)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR - fail")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_quantizations_thresholds(self):
        for mac_port in self.mac_ports:
            lst_thresholds = []
            for i in range(0, sdk.la_mac_port.OSTC_TRAFFIC_CLASSES):
                lst_thresholds.append(0.5 + (i / 10))

            thresholds = sdk.ostc_thresholds()
            thresholds.thresholds = lst_thresholds
            mac_port.set_ostc_quantizations(thresholds)

            res_thresholds = mac_port.get_ostc_quantizations()
            for i in range(0, sdk.la_mac_port.OSTC_TRAFFIC_CLASSES):
                self.assertAlmostEqual(res_thresholds.thresholds[i], lst_thresholds[i], delta=0.1)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_port_tc_for_fixed_protocol(self):
        for mac_port in self.mac_ports:
            for i in range(8):
                mac_port.set_port_tc_for_fixed_protocol(sdk.la_mac_port.tc_protocol_e_ETHERNET, i, i, (2 * i) % 4, (2 * i) % 8)
            for i in range(8):
                ostc, itc = mac_port.get_port_tc_for_fixed_protocol(sdk.la_mac_port.tc_protocol_e_ETHERNET, i)
                self.assertEqual(ostc, (2 * i) % 4)
                self.assertEqual(itc, (2 * i) % 8)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_port_tc_clear_and_access(self):
        for mac_port in self.mac_ports:
            for i in range(8):
                mac_port.set_port_tc_for_fixed_protocol(sdk.la_mac_port.tc_protocol_e_ETHERNET, i, i, (2 * i) % 4, (2 * i) % 8)

            mac_port.clear_port_tc_for_fixed_protocol()

            for i in range(8):
                with self.assertRaises(sdk.NotFoundException):
                    mac_port.get_port_tc_for_fixed_protocol(sdk.la_mac_port.tc_protocol_e_ETHERNET, i)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_port_tc_clear_and_reset(self):
        for mac_port in self.mac_ports:
            for i in range(8):
                mac_port.set_port_tc_for_fixed_protocol(sdk.la_mac_port.tc_protocol_e_ETHERNET, i, i, (2 * i) % 4, (2 * i) % 8)

            mac_port.clear_port_tc_for_fixed_protocol()

            for i in range(8):
                mac_port.set_port_tc_for_fixed_protocol(sdk.la_mac_port.tc_protocol_e_ETHERNET, i, i, (2 * i) % 4, (2 * i) % 8)
            for i in range(8):
                ostc, itc = mac_port.get_port_tc_for_fixed_protocol(sdk.la_mac_port.tc_protocol_e_ETHERNET, i)
                self.assertEqual(ostc, (2 * i) % 4)
                self.assertEqual(itc, (2 * i) % 8)

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_port_tc_tcam_exceedance_clear_and_set(self):
        for mac_port in self.mac_ports:
            for i in range(8):
                mac_port.set_port_tc_for_fixed_protocol(sdk.la_mac_port.tc_protocol_e_ETHERNET, i, i, (2 * i) % 4, (2 * i) % 8)
                mac_port.set_port_tc_for_fixed_protocol(sdk.la_mac_port.tc_protocol_e_IPV4, i, i, (2 * i) % 4, (2 * i) % 8)
            with self.assertRaises(sdk.ResourceException):
                mac_port.set_port_tc_for_fixed_protocol(sdk.la_mac_port.tc_protocol_e_IPV6, 0, 0, 0, 0)

            mac_port.clear_port_tc_for_fixed_protocol()

            for i in range(8):
                mac_port.set_port_tc_for_fixed_protocol(sdk.la_mac_port.tc_protocol_e_IPV6, i, i, (2 * i) % 4, (2 * i) % 8)
            for i in range(8):
                ostc, itc = mac_port.get_port_tc_for_fixed_protocol(sdk.la_mac_port.tc_protocol_e_IPV6, i)
                self.assertEqual(ostc, (2 * i) % 4)
                self.assertEqual(itc, (2 * i) % 8)

            mac_port.clear_port_tc_for_fixed_protocol()

    def create_shared_ports(self):
        s_mac_port0_params = [1, 1, 0, 0, sdk.la_mac_port.port_speed_e_E_25G,
                              sdk.la_mac_port.fc_mode_e_NONE, sdk.la_mac_port.fec_mode_e_NONE]
        s_mac_port1_params = [1, 1, 1, 1, sdk.la_mac_port.port_speed_e_E_25G,
                              sdk.la_mac_port.fc_mode_e_NONE, sdk.la_mac_port.fec_mode_e_NONE]

        self.s_mac_ports = []
        for mac_port_params in [s_mac_port0_params, s_mac_port1_params]:
            slice_id, ifg_id, serdes_start, serdes_last, speed, fc_mode, fec_mode = mac_port_params
            mac_port = self.device.create_mac_port(slice_id, ifg_id, serdes_start, serdes_last, speed, fc_mode, fec_mode)
            self.s_mac_ports.append(mac_port)

    @unittest.skip("Any two ports in the same MAC pool will clear each other's entries")
    def test_port_shared_tc_tcam(self):
        self.create_shared_ports()

        for i in range(8):
            self.s_mac_ports[0].set_port_tc_for_fixed_protocol(
                sdk.la_mac_port.tc_protocol_e_ETHERNET, i, i, (2 * i) %
                4, (2 * i) %
                8)
            self.s_mac_ports[1].set_port_tc_for_fixed_protocol(
                sdk.la_mac_port.tc_protocol_e_ETHERNET, i, i, (2 * i) %
                4, (2 * i) %
                8)

        self.s_mac_ports[0].clear_port_tc_for_fixed_protocol()

        for i in range(8):
            ostc, itc = self.s_mac_ports[1].get_port_tc_for_fixed_protocol(sdk.la_mac_port.tc_protocol_e_ETHERNET, i)
            self.assertEqual(ostc, (2 * i) % 4)
            self.assertEqual(itc, (2 * i) % 8)


if __name__ == '__main__':
    unittest.main()
