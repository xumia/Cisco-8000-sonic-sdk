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

import unittest
import decor
from leaba import sdk


@unittest.skipIf(decor.is_hw_device(), "Skip for HW device.")
class property_set_get(unittest.TestCase):

    def setUp(self):
        self.device = sdk.la_create_device('/dev/testdev', 0)
        self.bool_properties_wich_need_init = {sdk.la_device_property_e_ENABLE_LPM_IP_CACHE,
                                               sdk.la_device_property_e_ENABLE_PACIFIC_SW_BASED_PFC,
                                               sdk.la_device_property_e_ENABLE_PFC_DEVICE_TUNING}
        # Some properties require other objects to be configured first.
        self.bool_properties_with_dependencies = {sdk.la_device_property_e_PACIFIC_PFC_HBM_ENABLED}

    def tearDown(self):
        sdk.la_destroy_device(self.device)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_bool_property(self):
        # Validate the default
        ret_val = self.device.get_bool_property(sdk.la_device_property_e_ENABLE_HBM)

        self.assertEqual(ret_val, False)

        # Write new value and validate
        for prop in range(sdk.la_device_property_e_FIRST_BOOLEAN_PROPERTY, sdk.la_device_property_e_LAST_BOOLEAN_PROPERTY + 1):
            is_supported = self.is_property_supported_in_device(prop)
            if not is_supported:
                continue
            val = self.device.get_bool_property(prop)
            if prop in self.bool_properties_with_dependencies:
                continue
            if prop in self.bool_properties_wich_need_init:
                continue
            new_val = not val
            self.device.set_bool_property(prop, new_val)
            val = self.device.get_bool_property(prop)
            self.assertEqual(val, new_val)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_bool_property_with_init(self):
        # Validate the default
        ret_val = self.device.get_bool_property(sdk.la_device_property_e_ENABLE_HBM)

        self.assertEqual(ret_val, False)

        self.device.initialize(sdk.la_device.init_phase_e_DEVICE)
        # Write new value and validate
        for prop in range(sdk.la_device_property_e_FIRST_BOOLEAN_PROPERTY, sdk.la_device_property_e_LAST_BOOLEAN_PROPERTY + 1):
            is_supported = self.is_property_supported_in_device(prop)
            if not is_supported:
                continue
            val = self.device.get_bool_property(prop)
            if prop in self.bool_properties_with_dependencies:
                continue
            if prop not in self.bool_properties_wich_need_init:
                continue
            new_val = not val
            self.device.set_bool_property(prop, new_val)
            val = self.device.get_bool_property(prop)
            self.assertEqual(val, new_val)

    @unittest.skipIf(decor.is_gibraltar(), "Device frequency is fixed on GB")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_int_property(self):
        # Validate the default
        ret_val = self.device.get_int_property(sdk.la_device_property_e_MINIMUM_FABRIC_PORTS_FOR_CONNECTIVITY)
        self.assertEqual(ret_val, 1)

        # Validate the default for MAX_COUNTER_THRESHOLD
        ret_val = self.device.get_int_property(sdk.la_device_property_e_MAX_COUNTER_THRESHOLD)
        self.assertEqual(ret_val, 1 << 30)

        # Validate MAX_NUM_PCL_GIDS, default = 0, range = 0-128
        prop = sdk.la_device_property_e_MAX_NUM_PCL_GIDS
        val = self.device.get_int_property(prop)
        self.assertEqual(val, 0)
        new_val = -1
        try:
            self.device.set_int_property(prop, new_val)
        except BaseException:
            new_val = self.device.get_int_property(prop)
        self.assertEqual(val, new_val)
        new_val = 129
        try:
            self.device.set_int_property(prop, new_val)
        except BaseException:
            new_val = self.device.get_int_property(prop)
        self.assertEqual(val, new_val)

        # Write new value and validate
        properties_with_max_value = {
            sdk.la_device_property_e_LPM_L2_MAX_SRAM_BUCKETS,
            sdk.la_device_property_e_HBM_LPM_FAVOR_MODE,
            sdk.la_device_property_e_LPM_TCAM_BANK_SIZE,
            sdk.la_device_property_e_LPTS_MAX_ENTRY_COUNTERS,
            sdk.la_device_property_e_MULTICAST_MCID_SCALE_THRESHOLD,
        }
        # these are properties that need to be set befor the device is fully initialized().
        # So they cannot be tested here and must be excluded
        excluded_properties = [
            sdk.la_device_property_e_CREDIT_SIZE_IN_BYTES,
            sdk.la_device_property_e_NUM_MULTIPORT_PHY,
            sdk.la_device_property_e_OOB_INJ_CREDITS,
            sdk.la_device_property_e_EFUSE_REFCLK_SETTINGS,
            sdk.la_device_property_e_DEV_REFCLK_SEL,
            sdk.la_device_property_e_MATILDA_MODEL_TYPE]

        for prop in range(sdk.la_device_property_e_FIRST_INTEGER_PROPERTY, sdk.la_device_property_e_LAST_INTEGER_PROPERTY + 1):
            if prop in excluded_properties:
                continue
            is_supported = self.is_property_supported_in_device(prop)
            if not is_supported:
                continue
            val = self.device.get_int_property(prop)
            # check min & max limits on affected integer properties
            if (prop in properties_with_max_value):
                new_val = val + 1
                try:
                    self.device.set_int_property(prop, new_val)
                except BaseException:
                    new_val = self.device.get_int_property(prop)
                self.assertEqual(val, new_val)

                new_val = -1
                try:
                    self.device.set_int_property(prop, new_val)
                except BaseException:
                    new_val = self.device.get_int_property(prop)
                self.assertEqual(val, new_val)

            # check to make sure integer property values are updated correctly.
            new_val = val - 1 if (prop in properties_with_max_value) else val + 1
            self.device.set_int_property(prop, new_val)
            val = self.device.get_int_property(prop)
            self.assertEqual(val, new_val)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_string_property(self):
        # Validate the default
        ret_val = self.device.get_string_property(sdk.la_device_property_e_SERDES_FW_FILE_NAME)

        if decor.is_gibraltar():
            expected_file_name = "res/srm_app_fw_image_0_33_1_1688.txt"
        elif decor.is_asic4():
            expected_file_name = "res/beagle.hex"
        elif decor.is_asic5():
            expected_file_name = "res/seahawk3ip_0_2_2_2.bin"
        else:  # pacific
            expected_file_name = "res/serdes.0x109e_208d_0a4.rom"
        self.assertEqual(ret_val, expected_file_name)

        ret_val = self.device.get_string_property(sdk.la_device_property_e_SBUS_MASTER_FW_FILE_NAME)
        self.assertEqual(ret_val, "res/sbus_master.0x1024_2001.rom")

        # Write new value and validate
        new_val = "abcd"
        for prop in range(sdk.la_device_property_e_FIRST_STRING_PROPERTY, sdk.la_device_property_e_LAST_STRING_PROPERTY + 1):
            self.device.set_string_property(prop, new_val)
            ret_val = self.device.get_string_property(prop)
            self.assertEqual(ret_val, new_val)

    def is_property_supported_in_device(self, property):
        if decor.is_pacific() == False:
            if property == sdk.la_device_property_e_LC_56_FABRIC_PORT_MODE:
                # The LC_56 port mode is a pacific-only feature
                return False
            if property == sdk.la_device_property_e_ENABLE_PBTS:
                 # PBTS is not supported on pacific yet
                return False
        if decor.is_gibraltar() == False:
            if property == sdk.la_device_property_e_STATISTICAL_METER_COUNTING:
                # The statistical meters own counting mode is a gibraltar-only feature
                return False

            if property == sdk.la_device_property_e_ENABLE_CLASS_ID_ACLS:
                # The CLASS ID mode is a GB-only feature
                return False

            if property == sdk.la_device_property_e_ENABLE_ECN_QUEUING:
                # ECN VoQ enablement is currently a GB-only feature
                return False

            # The serdes LDO voltage regulator is a gibraltar-only feature
            # RXA power sequence mode is gibraltar-only feature. Exist in FW-1317 and up only.
            if property in [
                    sdk.la_device_property_e_ENABLE_SERDES_LDO_VOLTAGE_REGULATOR,
                    sdk.la_device_property_e_SERDES_RXA_POWER_SEQUENCE_MODE,
                    sdk.la_device_property_e_SERDES_CL136_PRESET_TYPE]:
                return False

            if property in [
                    sdk.la_device_property_e_ENABLE_SRM_OVERRIDE_PLL_KP_KF]:
                return False

        if (decor.is_gibraltar() == False) and (decor.is_pacific() == False):
            if property == sdk.la_device_property_e_LPM_TCAM_NUM_BANKSETS:
                return False
            if property == sdk.la_device_property_e_METER_BUCKET_REFILL_POLLING_DELAY:
                return False

        if decor.is_asic5():
            if property in [
                    sdk.la_device_property_e_LC_ADVERTISE_DEVICE_ON_FABRIC_MODE,
                    sdk.la_device_property_e_LC_FORCE_FORWARD_THROUGH_FABRIC_MODE,
                    sdk.la_device_property_e_ENABLE_NARROW_COUNTERS]:
                return False

        if decor.is_asic3() == False:
            if property == sdk.la_device_property_e_ENABLE_INFO_PHY:
                # The InFO Phy is a GR-only feature
                return False

        if decor.is_asic4():
            unsupported_device_properties = [
                sdk.la_device_property_e_STATISTICAL_METER_MULTIPLIER,
                sdk.la_device_property_e_TEMPERATURE_SENSOR_POLL_FAILURE_TIMEOUT_MILLISECONDS,
                sdk.la_device_property_e_AAPL_IFG_DELAY_BEFORE_EXEC,
                sdk.la_device_property_e_AAPL_HBM_DELAY_BEFORE_EXEC,
                sdk.la_device_property_e_AAPL_IFG_DELAY_BEFORE_POLL,
                sdk.la_device_property_e_AAPL_HBM_DELAY_BEFORE_POLL,
                sdk.la_device_property_e_AAPL_IFG_DELAY_IN_POLL,
                sdk.la_device_property_e_AAPL_IFG_POLL_TIMEOUT,
                sdk.la_device_property_e_LPTS_MAX_ENTRY_COUNTERS,
                sdk.la_device_property_e_MAC_PORT_SAVE_STATE_SERDES_DEBUG_SNAPSHOTS,
                sdk.la_device_property_e_DEV_REFCLK_SEL,
                sdk.la_device_property_e_EFUSE_REFCLK_SETTINGS,
                sdk.la_device_property_e_LC_56_FABRIC_PORT_MODE,
                sdk.la_device_property_e_PACIFIC_PFC_PILOT_PROBABILITY,
                sdk.la_device_property_e_PACIFIC_PFC_MEASUREMENT_PROBABILITY,
                sdk.la_device_property_e_MATILDA_MODEL_TYPE,
                sdk.la_device_property_e_ENABLE_NARROW_COUNTERS,
                sdk.la_device_property_e_LPM_TCAM_NUM_BANKSETS,
                sdk.la_device_property_e_LINKUP_TIME_BEFORE_SERDES_REFRESH,
                sdk.la_device_property_e_COUNTERS_SHADOW_AGE_OUT
            ]

            if property in unsupported_device_properties:
                return False

        return True


if __name__ == '__main__':
    unittest.main()
