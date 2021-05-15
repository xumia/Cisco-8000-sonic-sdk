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
import sys
import unittest
from leaba import sdk
import ip_test_base
from packet_test_utils import *
from scapy.all import *
import topology as T
from l3_ac_base import *
import ip_test_base
import sim_utils
import mtu.mtu_test_utils as MTU


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_port_mirroring_with_acl(l3_ac_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_ingress_mirroring_with_acl(self):
        self.add_l3_acl()

        self.topology.rx_l3_ac.hld_obj.set_ingress_mirror_command(self.ingress_mirror_cmd, is_acl_conditioned=False)
        run_and_compare_list(self, self.device, self.in_packet_data, [self.out_packet_data, self.ingress_punt_packet_data])
        mirror_cmd, is_acl_conditioned = self.topology.rx_l3_ac.hld_obj.get_ingress_mirror_command()
        self.assertEqual(mirror_cmd.get_gid(), self.ingress_mirror_cmd.get_gid())
        self.assertFalse(is_acl_conditioned)

        self.topology.rx_l3_ac.hld_obj.set_ingress_mirror_command(self.ingress_mirror_cmd, is_acl_conditioned=True)
        run_and_compare_list(self, self.device, self.in_packet_data, [self.out_packet_data, self.ingress_punt_packet_data])
        mirror_cmd, is_acl_conditioned = self.topology.rx_l3_ac.hld_obj.get_ingress_mirror_command()
        self.assertEqual(mirror_cmd.get_gid(), self.ingress_mirror_cmd.get_gid())
        self.assertTrue(is_acl_conditioned)

        self.clear_l3_acl()
        self.add_l3_acl(is_mirror=False, is_drop=False)

        self.topology.rx_l3_ac.hld_obj.set_ingress_mirror_command(self.ingress_mirror_cmd, is_acl_conditioned=False)
        run_and_compare_list(self, self.device, self.in_packet_data, [self.out_packet_data, self.ingress_punt_packet_data])
        mirror_cmd, is_acl_conditioned = self.topology.rx_l3_ac.hld_obj.get_ingress_mirror_command()
        self.assertEqual(mirror_cmd.get_gid(), self.ingress_mirror_cmd.get_gid())
        self.assertFalse(is_acl_conditioned)

        self.topology.rx_l3_ac.hld_obj.set_ingress_mirror_command(self.ingress_mirror_cmd, is_acl_conditioned=True)
        run_and_compare_list(self, self.device, self.in_packet_data, [self.out_packet_data])
        mirror_cmd, is_acl_conditioned = self.topology.rx_l3_ac.hld_obj.get_ingress_mirror_command()
        self.assertEqual(mirror_cmd.get_gid(), self.ingress_mirror_cmd.get_gid())
        self.assertTrue(is_acl_conditioned)

    @unittest.skipIf(decor.is_hw_device(), "Waiting outbound mirroring to be enabled on HW device")
    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_egress_mirroring_with_acl(self):
        self.add_l3_egress_acl()

        self.topology.tx_l3_ac_def.hld_obj.set_egress_mirror_command(self.egress_mirror_cmd, is_acl_conditioned=False)
        run_and_compare_list(self, self.device, self.in_packet_data, [self.out_packet_data, self.egress_punt_packet_data])
        mirror_cmd, is_acl_conditioned = self.topology.tx_l3_ac_def.hld_obj.get_egress_mirror_command()
        self.assertEqual(mirror_cmd.get_gid(), self.egress_mirror_cmd.get_gid())
        self.assertFalse(is_acl_conditioned)

        self.topology.tx_l3_ac_def.hld_obj.set_egress_mirror_command(self.egress_mirror_cmd, is_acl_conditioned=True)
        run_and_compare_list(self, self.device, self.in_packet_data, [self.out_packet_data, self.egress_punt_packet_data])
        mirror_cmd, is_acl_conditioned = self.topology.tx_l3_ac_def.hld_obj.get_egress_mirror_command()
        self.assertEqual(mirror_cmd.get_gid(), self.egress_mirror_cmd.get_gid())
        self.assertTrue(is_acl_conditioned)

        self.clear_l3_egress_acl()
        self.add_l3_egress_acl(is_mirror=False, is_drop=False)

        self.topology.tx_l3_ac_def.hld_obj.set_egress_mirror_command(self.egress_mirror_cmd, is_acl_conditioned=False)
        run_and_compare_list(self, self.device, self.in_packet_data, [self.out_packet_data, self.egress_punt_packet_data])
        mirror_cmd, is_acl_conditioned = self.topology.tx_l3_ac_def.hld_obj.get_egress_mirror_command()
        self.assertEqual(mirror_cmd.get_gid(), self.egress_mirror_cmd.get_gid())
        self.assertFalse(is_acl_conditioned)

        self.topology.tx_l3_ac_def.hld_obj.set_egress_mirror_command(self.egress_mirror_cmd, is_acl_conditioned=True)
        run_and_compare_list(self, self.device, self.in_packet_data, [self.out_packet_data])
        mirror_cmd, is_acl_conditioned = self.topology.tx_l3_ac_def.hld_obj.get_egress_mirror_command()
        self.assertEqual(mirror_cmd.get_gid(), self.egress_mirror_cmd.get_gid())
        self.assertTrue(is_acl_conditioned)

    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_ingress_mirroring_with_acl_mtu(self):
        self.add_l3_acl(is_mirror=False, is_drop=False)

        self.topology.rx_l3_ac.hld_obj.set_ingress_mirror_command(self.ingress_mirror_cmd, is_acl_conditioned=False)
        MTU.run_mtu_tests(self, self.device, self.in_packet_data, [self.out_packet_data, self.ingress_punt_packet_data])

    @unittest.skipIf(decor.is_hw_device(), "Waiting outbound mirroring to be enabled on HW device")
    @unittest.skipIf(decor.is_asic3(), "RTF is not yet enabled on GR")
    def test_egress_mirroring_with_acl_mtu(self):
        self.add_l3_egress_acl(is_mirror=False, is_drop=False)

        self.topology.tx_l3_ac_def.hld_obj.set_egress_mirror_command(self.egress_mirror_cmd, is_acl_conditioned=False)
        MTU.run_mtu_tests(self, self.device, self.in_packet_data, [self.out_packet_data, self.egress_punt_packet_data])


if __name__ == '__main__':
    unittest.main()
