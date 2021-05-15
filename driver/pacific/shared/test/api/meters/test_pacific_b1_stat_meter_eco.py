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

from leaba import sdk
import os
import decor
from sdk_test_case_base import *

MEGA = 1024 * 1024


@unittest.skipIf(decor.is_hw_device(), "No need to run on HW")
@unittest.skipIf(not decor.is_pacific(), "Relevant only for Pacific")
class unit_test(sdk_test_case_base):
    @staticmethod
    def almost_equal(a, b):
        TOLERANCE = 0.07
        ratio = a / b
        return ((ratio > (1 - TOLERANCE)) and (ratio < (1 + TOLERANCE)))

    @classmethod
    def setUpClass(cls):
        os.environ['ASIC'] = 'PACIFIC_B1'
        super(unit_test, cls).setUpClass()

    def setUp(self):
        super().setUp()

        self.exact_meter = self.device.create_meter(sdk.la_meter_set.type_e_EXACT, 1)
        self.exact_meter.set_committed_bucket_coupling_mode(0, sdk.la_meter_set.coupling_mode_e_TO_EXCESS_BUCKET)
        self.stat_meter = self.device.create_meter(sdk.la_meter_set.type_e_STATISTICAL, 1)
        self.stat_meter.set_committed_bucket_coupling_mode(0, sdk.la_meter_set.coupling_mode_e_TO_EXCESS_BUCKET)
        self.stat_meter.set_meter_action_profile(0, self.topology.meter_action_profile_def)
        self.packets_meter_profile = self.device.create_meter_profile(sdk.la_meter_profile.type_e_GLOBAL,
                                                                      sdk.la_meter_profile.meter_measure_mode_e_PACKETS,
                                                                      sdk.la_meter_profile.meter_rate_mode_e_SR_TCM,
                                                                      sdk.la_meter_profile.color_awareness_mode_e_AWARE)

        self.global_bytes_meter_profile = self.device.create_meter_profile(sdk.la_meter_profile.type_e_GLOBAL,
                                                                           sdk.la_meter_profile.meter_measure_mode_e_BYTES,
                                                                           sdk.la_meter_profile.meter_rate_mode_e_SR_TCM,
                                                                           sdk.la_meter_profile.color_awareness_mode_e_AWARE)

        self.per_ifg_bytes_meter_profile = self.device.create_meter_profile(sdk.la_meter_profile.type_e_PER_IFG,
                                                                            sdk.la_meter_profile.meter_measure_mode_e_BYTES,
                                                                            sdk.la_meter_profile.meter_rate_mode_e_SR_TCM,
                                                                            sdk.la_meter_profile.color_awareness_mode_e_AWARE)

    def test_attach_per_ifg_profile_to_statistical_meter(self):
        with self.assertRaises(sdk.InvalException):
            self.stat_meter.set_meter_profile(0, self.per_ifg_bytes_meter_profile)

    def test_attach_bytes_profile_to_statistical_meter(self):
        with self.assertRaises(sdk.InvalException):
            self.stat_meter.set_meter_profile(0, self.global_bytes_meter_profile)

    def test_set_measure_type(self):
        self.global_bytes_meter_profile.set_meter_measure_mode(sdk.la_meter_profile.meter_measure_mode_e_PACKETS)
        self.global_bytes_meter_profile.set_meter_measure_mode(sdk.la_meter_profile.meter_measure_mode_e_BYTES)

    def test_set_measure_type_after_setting_cbs(self):
        self.global_bytes_meter_profile.set_cbs(1024 * 2)
        with self.assertRaises(sdk.BusyException):
            self.global_bytes_meter_profile.set_meter_measure_mode(sdk.la_meter_profile.meter_measure_mode_e_PACKETS)

    def test_set_measure_type_after_setting_ebs(self):
        self.global_bytes_meter_profile.set_ebs_or_pbs(1024 * 2)
        with self.assertRaises(sdk.BusyException):
            self.global_bytes_meter_profile.set_meter_measure_mode(sdk.la_meter_profile.meter_measure_mode_e_PACKETS)

    def test_pps_cbs_precision(self):
        p = self.device.get_precision(sdk.la_precision_type_e_METER_PROFILE__STATISTICAL_METER_CBS_RESOLUTION)
        self.assertEqual(p, 128)

    def test_pps_ebs_precision(self):
        p = self.device.get_precision(sdk.la_precision_type_e_METER_PROFILE__STATISTICAL_METER_EBS_RESOLUTION)
        self.assertEqual(p, 128)

    def test_set_low_cbs(self):
        self.packets_meter_profile.set_cbs(128)
        cbs = self.packets_meter_profile.get_cbs()
        self.assertEqual(cbs, 128)

    def test_set_low_ebs(self):
        self.packets_meter_profile.set_ebs_or_pbs(128)
        ebs = self.packets_meter_profile.get_ebs_or_pbs()
        self.assertEqual(ebs, 128)

    def test_set_high_cbs(self):
        self.packets_meter_profile.set_cbs(MEGA // 8)
        cbs = self.packets_meter_profile.get_cbs()
        self.assertEqual(cbs, MEGA // 8)

    def test_set_high_ebs(self):
        self.packets_meter_profile.set_ebs_or_pbs(MEGA // 8)
        ebs = self.packets_meter_profile.get_ebs_or_pbs()
        self.assertEqual(ebs, MEGA // 8)

    def test_set_low_cir(self):
        self.stat_meter.set_meter_profile(0, self.packets_meter_profile)
        self.stat_meter.set_cir(0, 71)
        cir = self.stat_meter.get_cir(0)
        self.assertEqual(cir, 71)

    def test_set_low_eir(self):
        self.stat_meter.set_meter_profile(0, self.packets_meter_profile)
        self.stat_meter.set_eir(0, 71)
        eir = self.stat_meter.get_eir(0)
        self.assertEqual(eir, 71)

    def test_set_high_cir(self):
        requested_cir = 8 * MEGA
        self.stat_meter.set_meter_profile(0, self.packets_meter_profile)
        self.stat_meter.set_cir(0, requested_cir)
        actual_cir = self.stat_meter.get_cir(0)
        self.assertTrue(unit_test.almost_equal(requested_cir, actual_cir))

    def test_set_high_eir(self):
        requested_eir = 8 * MEGA
        self.stat_meter.set_meter_profile(0, self.packets_meter_profile)
        self.stat_meter.set_eir(0, requested_eir)
        actual_eir = self.stat_meter.get_eir(0)
        self.assertTrue(unit_test.almost_equal(requested_eir, actual_eir))


if __name__ == '__main__':
    unittest.main()
