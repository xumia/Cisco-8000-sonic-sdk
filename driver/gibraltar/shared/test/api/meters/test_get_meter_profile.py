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

import sys
import unittest
from leaba import sdk
from scapy.all import *
from meter_getters_base import *
import sim_utils
import topology as T
import packet_test_utils as U
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class get_meter_profile(meter_getters_base):

    def setUp(self):
        super().setUp()
        self.slice_ifg = sdk.la_slice_ifg()
        self.slice_ifg.ifg = T.get_device_ifg(2)
        self.slice_ifg.slice = T.get_device_slice(2)
        self.exact_meter = self.device.create_meter(sdk.la_meter_set.type_e_EXACT, 1)
        self.exact_meter.set_committed_bucket_coupling_mode(0, sdk.la_meter_set.coupling_mode_e_TO_EXCESS_BUCKET)
        self.per_ifg_exact_meter = self.device.create_meter(sdk.la_meter_set.type_e_PER_IFG_EXACT, 1)
        self.stat_meter = self.device.create_meter(sdk.la_meter_set.type_e_STATISTICAL, 1)

    def set_get_assert_meter_profile_action_helper(
            self,
            meter_action_profile,
            meter_color,
            rate_limiter_color,
            drop_enable,
            mark_ecn,
            packet_color,
            rx_cgm_color):
        meter_action_profile.set_action(
            meter_color, rate_limiter_color, drop_enable, mark_ecn, packet_color, rx_cgm_color)

        (res_drop_enable, res_mark_ecn, res_packet_color, res_rx_cgm_color) = \
            meter_action_profile.get_action(meter_color, rate_limiter_color)
        self.assertEqual(res_drop_enable, drop_enable)
        self.assertEqual(res_mark_ecn, mark_ecn)
        self.assertEqual(res_packet_color, packet_color)
        self.assertEqual(res_rx_cgm_color, rx_cgm_color)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_create_get_meter_profile(self):
        # Create meter profile
        for type in self.meter_profile_types:
            for measure_mode in self.meter_profile_measure_modes:
                for rate_mode in self.meter_profile_rate_modes:
                    for aware_mode in self.meter_profile_aware_modes:
                        meter_profile = self.device.create_meter_profile(type, measure_mode, rate_mode, aware_mode)
                        res_meter_profile_type = meter_profile.get_type()
                        self.assertEqual(res_meter_profile_type, type)

                        # Verify attribiutes
                        res_meter_measure_mode = meter_profile.get_meter_measure_mode()
                        self.assertEqual(res_meter_measure_mode, measure_mode)

                        res_meter_rate_mode = meter_profile.get_meter_rate_mode()
                        self.assertEqual(res_meter_rate_mode, rate_mode)

                        res_color_awareness_mode = meter_profile.get_color_awareness_mode()
                        self.assertEqual(res_color_awareness_mode, aware_mode)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_global_set_get_meter_profile_burst_size(self):
        # For la_meter_profile.type_e_GLOBAL - no set cbs/ebs_or_pbs per ifg is allowed

        meter_profile = self.device.create_meter_profile(sdk.la_meter_profile.type_e_GLOBAL,
                                                         sdk.la_meter_profile.meter_measure_mode_e_BYTES,
                                                         sdk.la_meter_profile.meter_rate_mode_e_SR_TCM,
                                                         sdk.la_meter_profile.color_awareness_mode_e_BLIND)

        res_cbs = meter_profile.get_cbs()
        self.assertEqual(res_cbs, self.DEFAULT_BURST_SIZE)

        # TODO: Implement destroy
        try:
            res_cbs = meter_profile.get_cbs(self.slice_ifg)
            self.assertFail()
        except sdk.BaseException:
            pass

        res_cbs = meter_profile.get_ebs_or_pbs()
        self.assertEqual(res_cbs, self.DEFAULT_BURST_SIZE)

        try:
            res_cbs = meter_profile.get_ebs_or_pbs(self.slice_ifg)
            self.assertFail()
        except sdk.BaseException:
            pass

        meter_profile.set_cbs(self.BURST_SIZE)
        res_cbs = meter_profile.get_cbs()
        self.assertEqual(res_cbs, self.BURST_SIZE)

        meter_profile.set_ebs_or_pbs(self.BURST_SIZE)
        res_ebs_or_pbs = meter_profile.get_ebs_or_pbs()
        self.assertEqual(res_ebs_or_pbs, self.BURST_SIZE)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_per_ifg_set_get_meter_profile_burst_size(self):
        # Test set rate functions for PER_IFG
        meter_profile = self.device.create_meter_profile(sdk.la_meter_profile.type_e_PER_IFG,
                                                         sdk.la_meter_profile.meter_measure_mode_e_BYTES,
                                                         sdk.la_meter_profile.meter_rate_mode_e_TR_TCM,
                                                         sdk.la_meter_profile.color_awareness_mode_e_BLIND)

        # For la_meter_profile.type_e_PER_IFG - no set cbs/ebs_or_pbs globally is allowed

        # TODO: Implement destroy
        try:
            res_cbs = meter_profile.get_cbs()
            self.assertFail()
        except sdk.BaseException:
            pass

        res_cbs = meter_profile.get_cbs(self.slice_ifg)
        self.assertEqual(res_cbs, self.DEFAULT_BURST_SIZE)

        # TODO: Implement destroy
        try:
            res_cbs = meter_profile.get_ebs_or_pbs()
            self.assertFail()
        except sdk.BaseException:
            pass

        res_cbs = meter_profile.get_ebs_or_pbs(self.slice_ifg)
        self.assertEqual(res_cbs, self.DEFAULT_BURST_SIZE)

        meter_profile.set_cbs(self.slice_ifg, self.BURST_SIZE)
        res_cbs = meter_profile.get_cbs(self.slice_ifg)
        self.assertEqual(res_cbs, self.BURST_SIZE)

        meter_profile.set_ebs_or_pbs(self.slice_ifg, self.BURST_SIZE)
        res_ebs_or_pbs = meter_profile.get_ebs_or_pbs(self.slice_ifg)
        self.assertEqual(res_ebs_or_pbs, self.BURST_SIZE)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_global_set_meter_profile_min_burst_size(self):
        # Test minimum value for set rate functions (Global)
        meter_profile = self.device.create_meter_profile(sdk.la_meter_profile.type_e_GLOBAL,
                                                         sdk.la_meter_profile.meter_measure_mode_e_BYTES,
                                                         sdk.la_meter_profile.meter_rate_mode_e_SR_TCM,
                                                         sdk.la_meter_profile.color_awareness_mode_e_AWARE)
        cbs = meter_profile.get_cbs()
        ebs_or_pbs = meter_profile.get_ebs_or_pbs()

        # test 0 (CBS) - Inval exception
        with self.assertRaises(sdk.InvalException):
            meter_profile.set_cbs(0)

        # check that the previous value remains the same
        # doesn't work on GB due to deffered nature of checking CBS validity
        if (not decor.is_gibraltar()):
            res_cbs = meter_profile.get_cbs()
            self.assertEqual(res_cbs, cbs)
        # test minimum limit (CBS) - Inval exception
        with self.assertRaises(sdk.InvalException):
            meter_profile.set_cbs(self.MIN_CBS - 1)
            if (decor.is_gibraltar()):
                nesto = self.exact_meter.get_meter_profile(0)
                self.exact_meter.set_meter_profile(0, meter_profile)

        # check that the previous value remains the same
        # doesn't work on GB due to deffered nature of checking CBS validity
        if (not decor.is_gibraltar()):
            res_cbs = meter_profile.get_cbs()
            self.assertEqual(res_cbs, cbs)

        # test 0 (EBS)
        with self.assertRaises(sdk.InvalException):
            meter_profile.set_ebs_or_pbs(0)

        # check that the previous value remains the same
        # doesn't work on GB due to deffered nature of checking EBS/PBS validity
        if (not decor.is_gibraltar()):
            res_ebs_or_pbs = meter_profile.get_ebs_or_pbs()
            self.assertEqual(res_ebs_or_pbs, ebs_or_pbs)

        # test minimum limit (EBS)
        with self.assertRaises(sdk.InvalException):
            meter_profile.set_ebs_or_pbs(self.MIN_EBS - 1)
            if (decor.is_gibraltar()):
                self.exact_meter.set_meter_profile(0, meter_profile)

        # check that the previous value remains the same
        # doesn't work on GB due to deffered nature of checking EBS/PBS validity
        if (not decor.is_gibraltar()):
            res_ebs_or_pbs = meter_profile.get_ebs_or_pbs()
            self.assertEqual(res_ebs_or_pbs, ebs_or_pbs)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_per_ifg_set_meter_profile_min_burst_size(self):
        # Test minimum value for set rate functions (PER_IFG)

        meter_profile = self.device.create_meter_profile(sdk.la_meter_profile.type_e_PER_IFG,
                                                         sdk.la_meter_profile.meter_measure_mode_e_BYTES,
                                                         sdk.la_meter_profile.meter_rate_mode_e_TR_TCM,
                                                         sdk.la_meter_profile.color_awareness_mode_e_BLIND)

        cbs = meter_profile.get_cbs(self.slice_ifg)
        ebs_or_pbs = meter_profile.get_ebs_or_pbs(self.slice_ifg)

        # test 0 (CBS) - Inval exception
        with self.assertRaises(sdk.InvalException):
            meter_profile.set_cbs(self.slice_ifg, 0)

        # check that the previous value remains the same
        res_cbs = meter_profile.get_cbs(self.slice_ifg)
        self.assertEqual(res_cbs, cbs)

        # test minimum limit (CBS)- Inval exception
        with self.assertRaises(sdk.InvalException):
            meter_profile.set_cbs(self.slice_ifg, self.MIN_CBS - 1)

        # check that the previous value remains the same
        res_cbs = meter_profile.get_cbs(self.slice_ifg)
        self.assertEqual(res_cbs, cbs)

        # test 0 (EBS)
        with self.assertRaises(sdk.InvalException):
            meter_profile.set_ebs_or_pbs(self.slice_ifg, 0)

        # check that the previous value remains the same
        res_ebs_or_pbs = meter_profile.get_ebs_or_pbs(self.slice_ifg)
        self.assertEqual(res_ebs_or_pbs, ebs_or_pbs)

        # test minimum limit (EBS)
        with self.assertRaises(sdk.InvalException):
            meter_profile.set_ebs_or_pbs(self.slice_ifg, self.MIN_EBS - 1)

        # check that the previous value remains the same
        res_ebs_or_pbs = meter_profile.get_ebs_or_pbs(self.slice_ifg)
        self.assertEqual(res_ebs_or_pbs, ebs_or_pbs)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_set_get_meter_profile_modes(self):
        # Test set functions
        meter_profile = self.device.create_meter_profile(
            sdk.la_meter_profile.type_e_GLOBAL,
            sdk.la_meter_profile.meter_measure_mode_e_BYTES,
            sdk.la_meter_profile.meter_rate_mode_e_TR_TCM,
            sdk.la_meter_profile.color_awareness_mode_e_BLIND)

        for measure_mode in self.meter_profile_measure_modes:
            meter_profile.set_meter_measure_mode(measure_mode)
            res_meter_measure_mode = meter_profile.get_meter_measure_mode()
            self.assertEqual(res_meter_measure_mode, measure_mode)

        for rate_mode in self.meter_profile_rate_modes:
            meter_profile.set_meter_rate_mode(rate_mode)
            res_meter_rate_mode = meter_profile.get_meter_rate_mode()
            self.assertEqual(res_meter_rate_mode, rate_mode)

        for aware_mode in self.meter_profile_aware_modes:
            meter_profile.set_color_awareness_mode(aware_mode)
            res_color_awareness_mode = meter_profile.get_color_awareness_mode()
            self.assertEqual(res_color_awareness_mode, aware_mode)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_get_meter_action_profile(self):
        # Create meter action profile
        meter_action_profile = self.device.create_meter_action_profile()

        for meter_color in self.COLOR_LST:
            for rate_limiter_color in self.COLOR_LST:

                # Verify default per color per attribiutes
                (res_drop_enable, res_mark_ecn, res_packet_color, res_rx_cgm_color) = \
                    meter_action_profile.get_action(meter_color, rate_limiter_color)
                self.assertEqual(res_drop_enable, True)
                self.assertEqual(res_mark_ecn, True)
                self.assertEqual(res_packet_color, sdk.la_qos_color_e_RED)
                self.assertEqual(res_rx_cgm_color, sdk.la_qos_color_e_YELLOW)

                # Test set functions
                for packet_color in self.COLOR_LST:
                    self.set_get_assert_meter_profile_action_helper(
                        meter_action_profile,
                        meter_color,
                        rate_limiter_color,
                        False,
                        False,
                        packet_color,
                        sdk.la_qos_color_e_GREEN)

                for rx_cgm_color in [sdk.la_qos_color_e_GREEN, sdk.la_qos_color_e_YELLOW]:
                    self.set_get_assert_meter_profile_action_helper(
                        meter_action_profile,
                        meter_color,
                        rate_limiter_color,
                        False,
                        False,
                        sdk.la_qos_color_e_GREEN,
                        rx_cgm_color)

                for drop_enabled in [True, False]:
                    self.set_get_assert_meter_profile_action_helper(
                        meter_action_profile,
                        meter_color,
                        rate_limiter_color,
                        drop_enabled,
                        False,
                        sdk.la_qos_color_e_GREEN,
                        sdk.la_qos_color_e_GREEN)

                for mark_ecn in [True, False]:
                    self.set_get_assert_meter_profile_action_helper(
                        meter_action_profile,
                        meter_color,
                        rate_limiter_color,
                        False,
                        mark_ecn,
                        sdk.la_qos_color_e_GREEN,
                        sdk.la_qos_color_e_GREEN)

        # Cleanup
        self.device.destroy(meter_action_profile)


if __name__ == '__main__':
    unittest.main()
