#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
from packet_test_utils import *
from scapy.all import *
import topology as T
import ip_test_base
import sim_utils
from hw_pfc_base import *
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
@unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
class test_hw_pfc(hw_pfc_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_hw_pfc_enable(self):
        self.mac_port.set_fc_mode(sdk.la_mac_port.fc_direction_e_BIDIR, sdk.la_mac_port.fc_mode_e_PFC)
        self.mac_port.set_pfc_enable(TC_BITMAP)

        (enabled, bitmap) = self.mac_port.get_pfc_enabled()
        self.assertEqual(bitmap, TC_BITMAP)

        self.mac_port.set_fc_mode(sdk.la_mac_port.fc_direction_e_BIDIR, sdk.la_mac_port.fc_mode_e_NONE)
        self.mac_port.set_pfc_disable()

        (enabled, bitmap) = self.mac_port.get_pfc_enabled()
        self.assertEqual(bitmap, TC_BITMAP_DISABLED)

        self.device.set_pfc_additional_link_tuning(True)
        self.device.set_pfc_additional_link_tuning(False)

        # Cannot enable PFC with no TC-s
        with self.assertRaises(sdk.InvalException):
            self.mac_port.set_pfc_enable(TC_BITMAP_FAIL)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_hw_pfc_port_settings(self):
        timer_value_1 = int((PORT_SPEED / PFC_QUANTA_BIT_VALUE) * TIMER_1)
        timer_value_2 = int((PORT_SPEED / PFC_QUANTA_BIT_VALUE) * TIMER_2)
        quanta_value_1 = int((PORT_SPEED / PFC_QUANTA_BIT_VALUE) * QUANTA_1)
        quanta_value_2 = int((PORT_SPEED / PFC_QUANTA_BIT_VALUE) * QUANTA_2)

        self.mac_port.set_pfc_periodic_timer(TIMER_1)

        self.assertEqual(self.mac_port.get_pfc_periodic_timer(), TIMER_1)

        self.mac_port.set_fc_mode(sdk.la_mac_port.fc_direction_e_BIDIR, sdk.la_mac_port.fc_mode_e_PFC)
        self.mac_port.set_pfc_enable(TC_BITMAP)

        self.mac_port.set_pfc_periodic_timer(TIMER_2)
        self.assertEqual(self.mac_port.get_pfc_periodic_timer(), TIMER_2)

        self.mac_port.set_pfc_quanta(QUANTA_1)
        self.assertEqual(self.mac_port.get_pfc_quanta(), QUANTA_1)

        self.mac_port.set_pfc_quanta(QUANTA_2)
        self.assertEqual(self.mac_port.get_pfc_quanta(), QUANTA_2)

        self.mac_port.set_fc_mode(sdk.la_mac_port.fc_direction_e_BIDIR, sdk.la_mac_port.fc_mode_e_NONE)
        self.mac_port.set_pfc_disable()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_hw_pfc_sqg_thresholds(self):
        self.device.set_rx_cgm_sqg_thresholds(SQG_1, SQG_THRESHOLDS_1)
        self.device.set_rx_cgm_sqg_thresholds(SQG_2, SQG_THRESHOLDS_2)
        thresholds_1 = self.device.get_rx_cgm_sqg_thresholds(SQG_1)
        thresholds_2 = self.device.get_rx_cgm_sqg_thresholds(SQG_2)
        self.assertListEqual(thresholds_1.thresholds, SQG_THRESHOLDS_1.thresholds)
        self.assertListEqual(thresholds_2.thresholds, SQG_THRESHOLDS_2.thresholds)

        self.device.set_rx_cgm_sqg_thresholds(SQG_1, SQG_THRESHOLDS_2)
        thresholds_1 = self.device.get_rx_cgm_sqg_thresholds(SQG_1)
        self.assertListEqual(thresholds_1.thresholds, SQG_THRESHOLDS_2.thresholds)

        with self.assertRaises(sdk.InvalException):
            self.device.set_rx_cgm_sqg_thresholds(SQG_1, SQG_THRESHOLDS_FAIL_1)

        with self.assertRaises(sdk.InvalException):
            self.device.set_rx_cgm_sqg_thresholds(SQG_1, SQG_THRESHOLDS_FAIL_2)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_hw_pfc_counter_a_thresholds(self):
        self.device.set_rx_cgm_sms_bytes_quantization(CTR_A_THRESHOLDS_1)
        thresholds = self.device.get_rx_cgm_sms_bytes_quantization()
        self.assertListEqual(thresholds.thresholds, CTR_A_THRESHOLDS_1.thresholds)

        self.device.set_rx_cgm_sms_bytes_quantization(CTR_A_THRESHOLDS_2)
        thresholds = self.device.get_rx_cgm_sms_bytes_quantization()
        self.assertListEqual(thresholds.thresholds, CTR_A_THRESHOLDS_2.thresholds)

        with self.assertRaises(sdk.InvalException):
            self.device.set_rx_cgm_sms_bytes_quantization(CTR_A_THRESHOLDS_FAIL_1)

        with self.assertRaises(sdk.InvalException):
            self.device.set_rx_cgm_sms_bytes_quantization(CTR_A_THRESHOLDS_FAIL_2)

        self.device.set_rx_pdr_sms_bytes_drop_thresholds(RXPDR_CTR_A_THRESHOLDS)
        thresholds = self.device.get_rx_pdr_sms_bytes_drop_thresholds()
        self.assertListEqual(thresholds.thresholds, RXPDR_CTR_A_THRESHOLDS.thresholds)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_hw_pfc_sq_profile_thresholds(self):
        profile_1 = self.device.create_rx_cgm_sq_profile()
        profile_2 = self.device.create_rx_cgm_sq_profile()
        profile_1.set_thresholds(SQ_THRESHOLDS_1)
        self.assertListEqual(profile_1.get_thresholds().thresholds, SQ_THRESHOLDS_1.thresholds)

        self.mac_port.set_tc_rx_cgm_sq_mapping(TC_1, profile_1, 0, 0)
        (sq_profile, sqg, drop_counter) = self.mac_port.get_tc_rx_cgm_sq_mapping(TC_1)
        self.assertEqual(sq_profile.oid(), profile_1.oid())

        profile_1.set_thresholds(SQ_THRESHOLDS_2)
        self.assertListEqual(profile_1.get_thresholds().thresholds, SQ_THRESHOLDS_2.thresholds)

        profile_2.set_thresholds(SQ_THRESHOLDS_1)
        self.assertListEqual(profile_2.get_thresholds().thresholds, SQ_THRESHOLDS_1.thresholds)

        self.mac_port.set_tc_rx_cgm_sq_mapping(TC_1, profile_2, 0, 0)
        (sq_profile, sqg, drop_counter) = self.mac_port.get_tc_rx_cgm_sq_mapping(TC_1)
        self.assertEqual(sq_profile.oid(), profile_2.oid())

        # Ensure multiple profiles on same mac port do not interfere
        self.mac_port.set_tc_rx_cgm_sq_mapping(TC_2, profile_1, 0, 0)
        (sq_profile, sqg, drop_counter) = self.mac_port.get_tc_rx_cgm_sq_mapping(TC_2)
        self.assertEqual(sq_profile.oid(), profile_1.oid())
        (sq_profile, sqg, drop_counter) = self.mac_port.get_tc_rx_cgm_sq_mapping(TC_1)
        self.assertEqual(sq_profile.oid(), profile_2.oid())

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_hw_pfc_sq_profile_policies(self):
        profile_1 = self.device.create_rx_cgm_sq_profile()
        profile_2 = self.device.create_rx_cgm_sq_profile()

        status_1 = sdk.la_rx_cgm_policy_status()
        status_1.counter_a_region = 1
        status_1.sq_profile_region = 2
        status_1.sq_group_region = 2
        # Profile 1, status 1 - [0, 1, 0]
        profile_1.set_rx_cgm_policy(status_1, False, True, False, False)
        # Profile 2, status 1 - [0, 1, 1]
        profile_2.set_rx_cgm_policy(status_1, False, True, True, True)

        status_2 = sdk.la_rx_cgm_policy_status()
        status_2.counter_a_region = 2
        status_2.sq_profile_region = 2
        status_2.sq_group_region = 2
        # Profile 1, status 2 - [0, 1, 1]
        profile_1.set_rx_cgm_policy(status_2, False, True, True, False)
        # Profile 2, status 2 - [1, 1, 1]
        profile_2.set_rx_cgm_policy(status_2, True, True, True, True)

        (fc, drop_yellow, drop_green, fc_trig) = profile_1.get_rx_cgm_policy(status_1)
        self.assertEqual(fc, False)
        self.assertEqual(drop_yellow, True)
        self.assertEqual(drop_green, False)
        self.assertEqual(fc_trig, False)
        (fc, drop_yellow, drop_green, fc_trig) = profile_2.get_rx_cgm_policy(status_1)
        self.assertEqual(fc, False)
        self.assertEqual(drop_yellow, True)
        self.assertEqual(drop_green, True)
        self.assertEqual(fc_trig, True)
        (fc, drop_yellow, drop_green, fc_trig) = profile_1.get_rx_cgm_policy(status_2)
        self.assertEqual(fc, False)
        self.assertEqual(drop_yellow, True)
        self.assertEqual(drop_green, True)
        self.assertEqual(fc_trig, False)
        (fc, drop_yellow, drop_green, fc_trig) = profile_2.get_rx_cgm_policy(status_2)
        self.assertEqual(fc, True)
        self.assertEqual(drop_yellow, True)
        self.assertEqual(drop_green, True)
        self.assertEqual(fc_trig, True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_hw_pfc_sq_mapping(self):
        profile_1 = self.device.create_rx_cgm_sq_profile()
        profile_2 = self.device.create_rx_cgm_sq_profile()

        self.mac_port.set_tc_rx_cgm_sq_mapping(TC_1, profile_1, SQG_1, DROP_COUNTER_1)
        self.mac_port.set_tc_rx_cgm_sq_mapping(TC_2, profile_2, SQG_2, DROP_COUNTER_2)
        (sq_profile, sqg, drop_counter) = self.mac_port.get_tc_rx_cgm_sq_mapping(TC_1)
        self.assertEqual(sq_profile.oid(), profile_1.oid())
        self.assertEqual(sqg, SQG_1)
        self.assertEqual(drop_counter, DROP_COUNTER_1)
        (sq_profile, sqg, drop_counter) = self.mac_port.get_tc_rx_cgm_sq_mapping(TC_2)
        self.assertEqual(sq_profile.oid(), profile_2.oid())
        self.assertEqual(sqg, SQG_2)
        self.assertEqual(drop_counter, DROP_COUNTER_2)

        self.mac_port.set_tc_rx_cgm_sq_mapping(TC_1, profile_2, SQG_2, DROP_COUNTER_2)
        (sq_profile, sqg, drop_counter) = self.mac_port.get_tc_rx_cgm_sq_mapping(TC_2)
        self.assertEqual(sq_profile.oid(), profile_2.oid())
        self.assertEqual(sqg, SQG_2)
        self.assertEqual(drop_counter, DROP_COUNTER_2)

        self.mac_port.set_tc_rx_cgm_sq_mapping(TC_1, profile_2, SQG_1, DROP_COUNTER_2)
        (sq_profile, sqg, drop_counter) = self.mac_port.get_tc_rx_cgm_sq_mapping(TC_1)
        self.assertEqual(sq_profile.oid(), profile_2.oid())
        self.assertEqual(sqg, SQG_1)
        self.assertEqual(drop_counter, DROP_COUNTER_2)

        self.mac_port.set_tc_rx_cgm_sq_mapping(TC_1, profile_2, SQG_1, DROP_COUNTER_1)
        (sq_profile, sqg, drop_counter) = self.mac_port.get_tc_rx_cgm_sq_mapping(TC_1)
        self.assertEqual(sq_profile.oid(), profile_2.oid())
        self.assertEqual(sqg, SQG_1)
        self.assertEqual(drop_counter, DROP_COUNTER_1)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_hw_pfc_default_profile(self):
        default_profile = self.device.get_default_rx_cgm_sq_profile()
        profile = self.device.create_rx_cgm_sq_profile()
        (sq_profile, sqg, drop_counter) = self.mac_port.get_tc_rx_cgm_sq_mapping(TC_2)
        self.assertEqual(sq_profile.oid(), default_profile.oid())
        self.assertEqual(sqg, DEFAULT_SQG)
        self.assertEqual(drop_counter, DEFAULT_DROP_COUNTER)

        default_profile.set_thresholds(SQ_THRESHOLDS_1)
        self.assertListEqual(default_profile.get_thresholds().thresholds, SQ_THRESHOLDS_1.thresholds)

        status = sdk.la_rx_cgm_policy_status()
        status.counter_a_region = 2
        status.sq_profile_region = 2
        status.sq_group_region = 2
        # Check default policy
        (fc, drop_yellow, drop_green, fc_trig) = default_profile.get_rx_cgm_policy(status)
        self.assertEqual(fc, False)
        self.assertEqual(drop_yellow, False)
        self.assertEqual(drop_green, False)
        self.assertEqual(fc_trig, False)
        default_profile.set_rx_cgm_policy(status, True, False, False, False)
        (fc, drop_yellow, drop_green, fc_trig) = default_profile.get_rx_cgm_policy(status)
        self.assertEqual(fc, True)
        self.assertEqual(drop_yellow, False)
        self.assertEqual(drop_green, False)
        self.assertEqual(fc_trig, False)

        self.mac_port.set_tc_rx_cgm_sq_mapping(TC_1, profile, SQG_2, DROP_COUNTER_2)
        (sq_profile, sqg, drop_counter) = self.mac_port.get_tc_rx_cgm_sq_mapping(TC_1)
        self.assertEqual(sq_profile.oid(), profile.oid())
        self.assertEqual(sqg, SQG_2)
        self.assertEqual(drop_counter, DROP_COUNTER_2)

        self.mac_port.set_tc_rx_cgm_sq_mapping(TC_1, default_profile, SQG_2, DROP_COUNTER_2)
        (sq_profile, sqg, drop_counter) = self.mac_port.get_tc_rx_cgm_sq_mapping(TC_1)
        self.assertEqual(sq_profile.oid(), default_profile.oid())
        self.assertEqual(sqg, SQG_2)
        self.assertEqual(drop_counter, DROP_COUNTER_2)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_hw_pfc_headroom_management(self):
        self.device.set_pfc_headroom_mode(sdk.la_rx_cgm_headroom_mode_e_THRESHOLD)

        default_profile = self.device.get_default_rx_cgm_sq_profile()
        default_profile.set_pfc_headroom_threshold(HR_THRESHOLD)
        self.assertEqual(default_profile.get_pfc_headroom_value(), HR_THRESHOLD)

        with self.assertRaises(sdk.InvalException):
            default_profile.set_pfc_headroom_timer(HR_TIMER)

        self.device.set_pfc_headroom_mode(sdk.la_rx_cgm_headroom_mode_e_TIMER)

        default_profile.set_pfc_headroom_timer(HR_TIMER)
        self.assertEqual(default_profile.get_pfc_headroom_value(), HR_TIMER)

        with self.assertRaises(sdk.InvalException):
            default_profile.set_pfc_headroom_threshold(HR_THRESHOLD)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_hw_pfc_profile_usage(self):
        for x in range(8):
            profile = self.device.create_rx_cgm_sq_profile()
            self.mac_port1.set_tc_rx_cgm_sq_mapping(x, profile, 0, 0)
        for x in range(7):
            profile = self.device.create_rx_cgm_sq_profile()
            self.mac_port.set_tc_rx_cgm_sq_mapping(x, profile, 0, 0)

        # Only 15 non-default profiles per slice - this should fail
        profile = self.device.create_rx_cgm_sq_profile()
        with self.assertRaises(sdk.ResourceException):
            self.mac_port.set_tc_rx_cgm_sq_mapping(7, profile, 0, 0)

        # Attach on new slice should succeed - profiles are per slice
        self.mac_port_other_slice.set_tc_rx_cgm_sq_mapping(0, profile, 0, 0)

        # Free a profile - this should allow for another attach
        default_profile = self.device.get_default_rx_cgm_sq_profile()
        self.mac_port.set_tc_rx_cgm_sq_mapping(0, default_profile, 0, 0)
        self.mac_port.set_tc_rx_cgm_sq_mapping(7, profile, 0, 0)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_hw_pfc_complete_config(self):
        # HR Management mode
        self.device.set_pfc_headroom_mode(sdk.la_rx_cgm_headroom_mode_e_THRESHOLD)

        # Counter A thresholds
        self.device.set_rx_cgm_sms_bytes_quantization(CTR_A_THRESHOLDS_1)

        # SQG thresholds
        self.device.set_rx_cgm_sqg_thresholds(SQG_1, SQG_THRESHOLDS_1)

        # SQ profile
        profile_1 = self.device.create_rx_cgm_sq_profile()
        status_1 = sdk.la_rx_cgm_policy_status()
        status_1.counter_a_region = 1
        status_1.sq_profile_region = 2
        status_1.sq_group_region = 2
        profile_1.set_rx_cgm_policy(status_1, False, True, False, False)
        profile_1.set_pfc_headroom_threshold(HR_THRESHOLD)
        profile_1.set_thresholds(SQ_THRESHOLDS_1)

        # Quanta value
        quanta_value_1 = int((PORT_SPEED / PFC_QUANTA_BIT_VALUE) * QUANTA_1)
        self.mac_port.set_pfc_quanta(QUANTA_1)

        # Periodic timer
        timer_value_1 = int((PORT_SPEED / PFC_QUANTA_BIT_VALUE) * TIMER_1)
        self.mac_port.set_pfc_periodic_timer(TIMER_1)

        # Mac port enable
        self.mac_port.set_fc_mode(sdk.la_mac_port.fc_direction_e_BIDIR, sdk.la_mac_port.fc_mode_e_PFC)
        self.mac_port.set_pfc_enable(TC_BITMAP)
        self.mac_port.set_pfc_tc_xoff_rx_enable(TC_BITMAP)

        # Mac port set mapping
        self.mac_port.set_tc_rx_cgm_sq_mapping(TC_1, profile_1, SQG_1, DROP_COUNTER_1)

        # Ensure SW PFC API-s error if HW PFC enabled
        with self.assertRaises(sdk.InvalException):
            self.pfc_tx_meter = self.device.create_meter(sdk.la_meter_set.type_e_PER_IFG_EXACT, 8)
            self.mac_port.set_pfc_meter(self.pfc_tx_meter)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_hw_pfc_system_tuning(self):
        # Test OQ profile modification on PFC enable
        port_speed = sdk.la_mac_port.port_speed_e_E_50G
        self.device.set_tx_cgm_port_oq_profile_thresholds(T.RX_SLICE, port_speed, OQ_THRESHOLDS)
        self.device.set_tx_cgm_pfc_port_oq_profile_thresholds(T.RX_SLICE, port_speed, OQ_THRESHOLDS)
        thresholds = self.device.get_tx_cgm_port_oq_profile_thresholds(T.RX_SLICE, port_speed)
        self.assertEqual(thresholds.fc_bytes_threshold, OQ_THRESHOLDS.fc_bytes_threshold)
        self.assertEqual(thresholds.fc_buffers_threshold, OQ_THRESHOLDS.fc_buffers_threshold)
        self.assertEqual(thresholds.fc_pds_threshold, OQ_THRESHOLDS.fc_pds_threshold)
        self.assertEqual(thresholds.drop_bytes_threshold, OQ_THRESHOLDS.drop_bytes_threshold)
        self.assertEqual(thresholds.drop_buffers_threshold, OQ_THRESHOLDS.drop_buffers_threshold)
        self.assertEqual(thresholds.drop_pds_threshold, OQ_THRESHOLDS.drop_pds_threshold)
        thresholds = self.device.get_tx_cgm_pfc_port_oq_profile_thresholds(T.RX_SLICE, port_speed)
        self.assertEqual(thresholds.fc_bytes_threshold, OQ_THRESHOLDS.fc_bytes_threshold)
        self.assertEqual(thresholds.fc_buffers_threshold, OQ_THRESHOLDS.fc_buffers_threshold)
        self.assertEqual(thresholds.fc_pds_threshold, OQ_THRESHOLDS.fc_pds_threshold)
        self.assertEqual(thresholds.drop_bytes_threshold, OQ_THRESHOLDS.drop_bytes_threshold)
        self.assertEqual(thresholds.drop_buffers_threshold, OQ_THRESHOLDS.drop_buffers_threshold)
        self.assertEqual(thresholds.drop_pds_threshold, OQ_THRESHOLDS.drop_pds_threshold)

        self.mac_port.set_pfc_oq_profile_tc_bitmap(TC_BITMAP)
        self.assertEqual(self.mac_port.get_pfc_oq_profile_tc_bitmap(), TC_BITMAP)

        # Test max negative credit balance API
        cb = 0x123
        self.device.set_voq_max_negative_credit_balance(cb)
        self.assertEqual(self.device.get_voq_max_negative_credit_balance(), cb)

        # Test Fabric rate limiter API-s
        self.device.set_fabric_sch_valid_links_quantization_thresholds(VALID_LINKS_THRESHOLDS_1)
        self.device.set_fabric_sch_valid_links_quantization_thresholds(VALID_LINKS_THRESHOLDS_2)

        self.device.set_fabric_sch_congested_links_quantization_thresholds(CONGESTED_LINKS_THRESHOLDS_1)
        self.device.set_fabric_sch_congested_links_quantization_thresholds(CONGESTED_LINKS_THRESHOLDS_2)

        self.device.set_fabric_sch_links_map_entry(0, 1, 2)  # Valid links region, Congested links region, rate map index
        self.device.set_fabric_sch_links_map_entry(1, 1, 3)

        self.device.set_fabric_sch_rate_map_entry(2, FABRIC_RATE_1)  # index, rate
        self.device.set_fabric_sch_rate_map_entry(3, FABRIC_RATE_2)


if __name__ == '__main__':
    unittest.main()
