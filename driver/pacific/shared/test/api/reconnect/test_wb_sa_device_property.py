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
from snake_base import *
import decor
import warm_boot_test_utils as wb
from wb_sa_base import *


@unittest.skip("Needs adjustments after merging WB with master")
@unittest.skipUnless(decor.is_hw_device(), "Requires HW device")
@unittest.skipUnless(decor.is_gibraltar(), "WB is only suppored for gibraltar")
class test_wb_sa(test_wb_sa_base):
    def test_wb_sa_device_property(self):
        '''
        check device property persistence across warmboot, no traffic testing
        '''
        print("checking device property")
        self.setup_ports()
        device = self.snake.device
        excluded_prop = [sdk.la_device_property_e_PACIFIC_PFC_PILOT_PROBABILITY,
                         sdk.la_device_property_e_PACIFIC_PFC_MEASUREMENT_PROBABILITY,
                         sdk.la_device_property_e_LC_56_FABRIC_PORT_MODE,
                         sdk.la_device_property_e_LC_FORCE_FORWARD_THROUGH_FABRIC_MODE,
                         sdk.la_device_property_e_LC_TYPE_2_4_T,
                         sdk.la_device_property_e_USING_LEABA_NIC,
                         sdk.la_device_property_e_ENABLE_NSIM_ACCURATE_SCALE_MODEL,
                         sdk.la_device_property_e_ENABLE_HBM,
                         sdk.la_device_property_e_TEST_MODE_PUNT_EGRESS_PACKETS_TO_HOST,
                         sdk.la_device_property_e_EMULATED_DEVICE,
                         sdk.la_device_property_e_ENABLE_HBM_ROUTE_EXTENSION,
                         sdk.la_device_property_e_ENABLE_MBIST_REPAIR,
                         sdk.la_device_property_e_IGNORE_MBIST_ERRORS,
                         sdk.la_device_property_e_ENABLE_NARROW_COUNTERS,
                         sdk.la_device_property_e_ENABLE_MPLS_SR_ACCOUNTING,
                         sdk.la_device_property_e_ENABLE_PACIFIC_B0_IFG_CHANGES,
                         sdk.la_device_property_e_ENABLE_PACIFIC_OOB_INTERLEAVING,
                         sdk.la_device_property_e_HBM_MOVE_TO_READ_ON_EMPTY,
                         sdk.la_device_property_e_HBM_MOVE_TO_WRITE_ON_EMPTY,
                         sdk.la_device_property_e_ENABLE_HBM_ROUTE_EXTENSION_CACHING_MODE,  # 16
                         sdk.la_device_property_e_ENABLE_LPM_IP_CACHE,  # 17
                         sdk.la_device_property_e_DISABLE_ELECTRICAL_IDLE_DETECTION,
                         sdk.la_device_property_e_INSTANTIATE_REMOTE_SYSTEM_PORTS,
                         sdk.la_device_property_e_ENABLE_SERDES_NRZ_FAST_TUNE,  # 28
                         sdk.la_device_property_e_ENABLE_NETWORK_SERDES_PAM4_FAST_TUNE,  # 29
                         sdk.la_device_property_e_ENABLE_FABRIC_SERDES_PAM4_FAST_TUNE,  # 30
                         sdk.la_device_property_e_HBM_FREQUENCY,
                         sdk.la_device_property_e_STATISTICAL_METER_MULTIPLIER,
                         sdk.la_device_property_e_TEMPERATURE_SENSOR_POLL_FAILURE_TIMEOUT_MILLISECONDS,
                         sdk.la_device_property_e_MINIMUM_FABRIC_PORTS_FOR_CONNECTIVITY,
                         sdk.la_device_property_e_MAC_PORT_SAVE_STATE_SERDES_DEBUG_SNAPSHOTS,
                         sdk.la_device_property_e_LPM_L2_MAX_SRAM_BUCKETS,
                         sdk.la_device_property_e_LPM_TCAM_NUM_BANKSETS,
                         sdk.la_device_property_e_LPM_TCAM_BANK_SIZE,
                         sdk.la_device_property_e_DEVICE_FREQUENCY,
                         sdk.la_device_property_e_TCK_FREQUENCY,
                         sdk.la_device_property_e_MAX_COUNTER_THRESHOLD,
                         sdk.la_device_property_e_AAPL_IFG_DELAY_BEFORE_EXEC,
                         sdk.la_device_property_e_AAPL_HBM_DELAY_BEFORE_EXEC,
                         sdk.la_device_property_e_AAPL_IFG_DELAY_BEFORE_POLL,
                         sdk.la_device_property_e_AAPL_HBM_DELAY_BEFORE_POLL,
                         sdk.la_device_property_e_AAPL_IFG_DELAY_IN_POLL,
                         sdk.la_device_property_e_AAPL_IFG_POLL_TIMEOUT,
                         sdk.la_device_property_e_HBM_READ_CYCLES,
                         sdk.la_device_property_e_HBM_WRITE_CYCLES,
                         sdk.la_device_property_e_HBM_MIN_MOVE_TO_READ,
                         sdk.la_device_property_e_HBM_LPM_FAVOR_MODE,
                         sdk.la_device_property_e_HBM_PHY_T_RDLAT_OFFSET,
                         sdk.la_device_property_e_LPTS_MAX_ENTRY_COUNTERS,
                         sdk.la_device_property_e_MAX_NUM_PCL_IDS,
                         sdk.la_device_property_e_LINKUP_TIME_BEFORE_SERDES_REFRESH,
                         sdk.la_device_property_e_EFUSE_REFCLK_SETTINGS,
                         sdk.la_device_property_e_DEV_REFCLK_SEL,
                         sdk.la_device_property_e_ENABLE_INFO_PHY]
        new_int_property_val = 3
        device_int_prop = [
            prop for prop in range(
                sdk.la_device_property_e_FIRST_INTEGER_PROPERTY,
                sdk.la_device_property_e_LAST_INTEGER_PROPERTY +
                1) if prop not in excluded_prop]
        for prop in device_int_prop:
            device.set_int_property(prop, new_int_property_val)

        new_bool_property_val = True
        device_bool_prop = [
            prop for prop in range(
                sdk.la_device_property_e_FIRST_BOOLEAN_PROPERTY,
                sdk.la_device_property_e_LAST_BOOLEAN_PROPERTY +
                1) if prop not in excluded_prop]
        for prop in device_bool_prop:
            device.set_bool_property(prop, new_bool_property_val)

        wb.warm_boot(device)
        # Restore notification pipes manually
        self.snake.mph.critical_fd, self.snake.mph.normal_fd = device.open_notification_fds(sdk.LA_NOTIFICATION_MASK_ALL)
        # make sure all the ports are up
        self.snake.mph.wait_mac_ports_up()
        for prop in device_int_prop:
            property_val = device.get_int_property(prop)
            self.assertEqual(property_val, new_int_property_val)
        for prop in device_bool_prop:
            property_val = device.get_bool_property(prop)
            self.assertEqual(property_val, new_bool_property_val)


if __name__ == '__main__':
    unittest.main()
