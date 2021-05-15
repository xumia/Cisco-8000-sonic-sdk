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
from leaba import sdk
import rpfo
import sim_utils
import decor
import time
import topology as T

verbose = 0


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_valgrind(), "Temporary skipped, valgrind takes hours or worse gets stuck")
@unittest.skipIf(decor.is_auto_warm_boot_enabled(), "Reconnect flow not supported with WB")
class test_reconnect(unittest.TestCase):

    def setUp(self):
        self.dev_id = 1
        self.uut_device = None
        if verbose >= 1:
            sdk.la_set_logging_level(self.dev_id, sdk.la_logger_component_e_RECONNECT, sdk.la_logger_level_e_DEBUG)

    def tearDown(self):
        if self.uut_device:
            self.uut_device.tearDown()
            self.uut_device = None

    @unittest.skipIf(decor.is_valgrind(), "Temporary disable due to failure")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_css_accessability(self):
        # Create a device that is not FABRIC_ELEMENT_DEV so that "reconnect"
        # functionality stays dormant and econrnect metadata is not written to CSS.
        self.uut_device = sim_utils.create_device(self.dev_id, slice_modes=sim_utils.STANDALONE_DEV)
        ldev = self.uut_device.get_ll_device()
        device_tree = sim_utils.get_device_tree(ldev)
        css = device_tree.sbif.css_mem_even

        if ldev.is_pacific():
            # First need to stop the ARC processors as they would be updating css memory.
            # FIXME: Once ARC is ported to GB remove this check
            ldev.stop_css_arcs()

        errors = 0
        for i in range(css.get_desc().entries // 2):
            ldev.write_memory(css, i, 0xdeadbeaf)
            val = ldev.read_memory(css, i)
            if val != 0xdeadbeaf:
                errors += 1
                if verbose >= 1:
                    print('css[{}]={}'.format(i, hex(val)))

        self.assertEqual(errors, 0)

    @unittest.skipIf(decor.is_asic4(), "FE mode is not supported on PL")
    @unittest.skipIf(decor.is_asic5(), "FE mode is not supported on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(),
                     "Matilda does not support Linecard and Fabric modes. Irrelevant test.")
    def test_device_parameters_persistency_across_reconnect(self):
        uut_device = sim_utils.create_device(self.dev_id, slice_modes=sim_utils.FABRIC_ELEMENT_DEV)
        uut_device.crit_fd, uut_device.norm_fd = uut_device.open_notification_fds(sdk.LA_NOTIFICATION_MASK_ALL)
        self.uut_device = uut_device

        ldev = self.uut_device.get_ll_device()

        token_in = 1000  # Arbitrary testing value
        uut_device.write_persistent_token(token_in)

        token_out = uut_device.read_persistent_token()
        self.assertEqual(token_in, token_out)

        token_in = 2000  # New value to be written to device
        uut_device.write_persistent_token(token_in)

        # Modify one property, set to non-default value
        property_poll_interval = uut_device.get_int_property(sdk.la_device_property_e_POLL_INTERVAL_MILLISECONDS)
        property_poll_interval += 100
        uut_device.set_int_property(sdk.la_device_property_e_POLL_INTERVAL_MILLISECONDS, property_poll_interval)

        # Read all properties
        properties_bool = {}
        properties_int = {}
        self.supported_boolean_device_properties = {
            p for p in range(
                sdk.la_device_property_e_FIRST_BOOLEAN_PROPERTY,
                sdk.la_device_property_e_LAST_BOOLEAN_PROPERTY + 1)}
        self.supported_int_device_properties = {
            p for p in range(
                sdk.la_device_property_e_FIRST_INTEGER_PROPERTY,
                sdk.la_device_property_e_LAST_INTEGER_PROPERTY + 1)}
        if ldev.is_gibraltar():
            exclude_gb_int_property_set = {sdk.la_device_property_e_STATISTICAL_METER_MULTIPLIER,
                                           sdk.la_device_property_e_TEMPERATURE_SENSOR_POLL_FAILURE_TIMEOUT_MILLISECONDS,
                                           sdk.la_device_property_e_AAPL_IFG_DELAY_BEFORE_EXEC,
                                           sdk.la_device_property_e_AAPL_HBM_DELAY_BEFORE_EXEC,
                                           sdk.la_device_property_e_AAPL_IFG_DELAY_BEFORE_POLL,
                                           sdk.la_device_property_e_AAPL_HBM_DELAY_BEFORE_POLL,
                                           sdk.la_device_property_e_AAPL_IFG_DELAY_IN_POLL,
                                           sdk.la_device_property_e_AAPL_IFG_POLL_TIMEOUT,
                                           sdk.la_device_property_e_LPTS_MAX_ENTRY_COUNTERS}
            self.supported_int_device_properties = self.supported_int_device_properties - exclude_gb_int_property_set
        else:
            exclude_pacific_boolean_property_set = {sdk.la_device_property_e_ENABLE_CLASS_ID_ACLS,
                                                    sdk.la_device_property_e_ENABLE_ECN_QUEUING,
                                                    sdk.la_device_property_e_ENABLE_SERDES_LDO_VOLTAGE_REGULATOR}
            self.supported_boolean_device_properties = self.supported_boolean_device_properties - exclude_pacific_boolean_property_set

        exclude_int_property_set = {
            sdk.la_device_property_e_OOB_INJ_CREDITS,
            sdk.la_device_property_e_EFUSE_REFCLK_SETTINGS,
            sdk.la_device_property_e_DEV_REFCLK_SEL,
            sdk.la_device_property_e_MINIMUM_FABRIC_PORTS_FOR_CONNECTIVITY}
        exclude_bool_property_set = {sdk.la_device_property_e_ENABLE_INFO_PHY}
        self.supported_int_device_properties = self.supported_int_device_properties - exclude_int_property_set
        self.supported_boolean_device_properties = self.supported_boolean_device_properties - exclude_bool_property_set
        print(self.supported_boolean_device_properties)
        print(self.supported_int_device_properties)
        for i in self.supported_boolean_device_properties:
            val = uut_device.get_bool_property(i)
            properties_bool[i] = val
        for i in self.supported_int_device_properties:
            val = uut_device.get_int_property(i)
            properties_int[i] = val
        self.assertEqual(properties_int[sdk.la_device_property_e_POLL_INTERVAL_MILLISECONDS], property_poll_interval)

        # Kill the device and reconnect
        rpfo.rpfo(self.uut_device, [], [])

        token_out = uut_device.read_persistent_token()
        self.assertEqual(token_in, token_out)

        for i in self.supported_boolean_device_properties:
            val = uut_device.get_bool_property(i)
            self.assertEqual(val, properties_bool[i])
        for i in self.supported_int_device_properties:
            val = uut_device.get_int_property(i)
            self.assertEqual(val, properties_int[i])

    @unittest.skipIf(decor.is_asic4(), "FE mode is not supported on PL")
    @unittest.skipIf(decor.is_asic5(), "FE mode is not supported on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(),
                     "Matilda does not support Linecard and Fabric modes. Irrelevant test.")
    def test_pvt_access_after_reconnect(self):
        if verbose >= 1:
            sdk.la_set_logging_level(self.dev_id, sdk.la_logger_component_e_PVT, sdk.la_logger_level_e_DEBUG)

        self.uut_device = sim_utils.create_device(self.dev_id, slice_modes=sim_utils.FABRIC_ELEMENT_DEV)

        self.uut_device.crit_fd, self.uut_device.norm_fd = self.uut_device.open_notification_fds(sdk.LA_NOTIFICATION_MASK_ALL)

        self.verify_pvt_access()

        # Kill the device and reconnect
        rpfo.rpfo(self.uut_device, [], [])

        self.verify_pvt_access()

    @unittest.skipIf(decor.is_asic4(), "FE mode is not supported on PL")
    @unittest.skipIf(decor.is_asic5(), "FE mode is not supported on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_matilda(),
                     "Matilda does not support Linecard and Fabric modes. Irrelevant test.")
    def test_serdes_params(self):
        self.uut_device = sim_utils.create_device(self.dev_id, slice_modes=sim_utils.FABRIC_ELEMENT_DEV)

        ldev = self.uut_device.get_ll_device()
        self.uut_device.crit_fd, self.uut_device.norm_fd = self.uut_device.open_notification_fds(sdk.LA_NOTIFICATION_MASK_ALL)

        # Create the max number of fabric ports
        mac_ports = []
        if ldev.is_gibraltar():
            max_serdes = [10, 8, 10, 8, 8, 10, 10, 8, 8, 10, 8, 10]
        else:
            max_serdes = [9] * 12
        for slice in self.uut_device.device.get_used_slices():
            for ifg in range(0, 2):
                for first_serdes in range(0, max_serdes[slice * 2 + ifg] * 2, 2):
                    print('creating mac port on {}/{}/{}'.format(slice, ifg, first_serdes))
                    mac_port = self.uut_device.create_fabric_mac_port(
                        slice,
                        ifg,
                        first_serdes,
                        first_serdes + 1,
                        sdk.la_mac_port.port_speed_e_E_100G,
                        sdk.la_mac_port.fc_mode_e_PFC)
                    mac_ports.append(mac_port)

        # Pacific can have up to 108 fabric ports
        self.assertEqual(len(mac_ports), 108)

        # For each port, set supported serdes params
        if ldev.is_gibraltar():
            stage = sdk.la_mac_port.serdes_param_stage_e_ACTIVATE
            self.supported_serdes_params = [sdk.la_mac_port.serdes_param_e_DATAPATH_RX_GRAY_MAP,
                                            sdk.la_mac_port.serdes_param_e_DATAPATH_TX_GRAY_MAP,
                                            sdk.la_mac_port.serdes_param_e_DATAPATH_RX_PRECODE,
                                            sdk.la_mac_port.serdes_param_e_DATAPATH_TX_PRECODE,
                                            sdk.la_mac_port.serdes_param_e_DATAPATH_RX_SWIZZLE,
                                            sdk.la_mac_port.serdes_param_e_DATAPATH_TX_SWIZZLE,
                                            sdk.la_mac_port.serdes_param_e_TX_POST,
                                            sdk.la_mac_port.serdes_param_e_TX_POST2,
                                            sdk.la_mac_port.serdes_param_e_TX_POST3,
                                            sdk.la_mac_port.serdes_param_e_TX_PRE1,
                                            sdk.la_mac_port.serdes_param_e_TX_PRE2,
                                            sdk.la_mac_port.serdes_param_e_TX_PRE3,
                                            sdk.la_mac_port.serdes_param_e_TX_MAIN,
                                            sdk.la_mac_port.serdes_param_e_TX_INNER_EYE1,
                                            sdk.la_mac_port.serdes_param_e_TX_INNER_EYE2,
                                            sdk.la_mac_port.serdes_param_e_TX_LUT_MODE,
                                            sdk.la_mac_port.serdes_param_e_RX_AC_COUPLING_BYPASS,
                                            sdk.la_mac_port.serdes_param_e_RX_AFE_TRIM,
                                            sdk.la_mac_port.serdes_param_e_RX_CTLE_CODE,
                                            sdk.la_mac_port.serdes_param_e_RX_DSP_MODE,
                                            sdk.la_mac_port.serdes_param_e_RX_VGA_TRACKING,
                                            sdk.la_mac_port.serdes_param_e_RX_SDT_CODE_FALL,
                                            sdk.la_mac_port.serdes_param_e_RX_SDT_CODE_RISE,
                                            sdk.la_mac_port.serdes_param_e_RX_SDT_CODE_TH,
                                            sdk.la_mac_port.serdes_param_e_RX_SDT_BLOCK_CNT]
        else:
            stage = sdk.la_mac_port.serdes_param_stage_e_PRE_PCAL
            self.supported_serdes_params = [sdk.la_mac_port.serdes_param_e_RX_CTLE_LF,
                                            sdk.la_mac_port.serdes_param_e_RX_CTLE_HF,
                                            sdk.la_mac_port.serdes_param_e_RX_CTLE_GAINSHAPE1,
                                            sdk.la_mac_port.serdes_param_e_RX_CTLE_GAINSHAPE2,
                                            sdk.la_mac_port.serdes_param_e_RX_CTLE_SHORT_CHANNEL_EN,
                                            sdk.la_mac_port.serdes_param_e_RX_FFE_PRE2,
                                            sdk.la_mac_port.serdes_param_e_RX_FFE_PRE1,
                                            sdk.la_mac_port.serdes_param_e_RX_FFE_POST,
                                            sdk.la_mac_port.serdes_param_e_RX_FFE_BFLF,
                                            sdk.la_mac_port.serdes_param_e_RX_FFE_BFHF,
                                            sdk.la_mac_port.serdes_param_e_RX_FFE_SHORT_CHANNEL_EN,
                                            sdk.la_mac_port.serdes_param_e_HYSTERESIS_POST1_NEGATIVE,
                                            sdk.la_mac_port.serdes_param_e_HYSTERESIS_POST1_POSETIVE,
                                            sdk.la_mac_port.serdes_param_e_DATAPATH_RX_PRECODE,
                                            sdk.la_mac_port.serdes_param_e_DATAPATH_TX_PRECODE,
                                            sdk.la_mac_port.serdes_param_e_DATAPATH_TX_SWIZZLE,
                                            sdk.la_mac_port.serdes_param_e_DATAPATH_RX_SWIZZLE,
                                            sdk.la_mac_port.serdes_param_e_DIVIDER,
                                            sdk.la_mac_port.serdes_param_e_ELECTRICAL_IDLE_THRESHOLD,
                                            sdk.la_mac_port.serdes_param_e_RX_CTLE_HF_MAX,
                                            sdk.la_mac_port.serdes_param_e_RX_CTLE_HF_MIN,
                                            sdk.la_mac_port.serdes_param_e_RX_CTLE_LF_MAX,
                                            sdk.la_mac_port.serdes_param_e_RX_CTLE_LF_MIN,
                                            sdk.la_mac_port.serdes_param_e_RX_CTLE_DC,
                                            sdk.la_mac_port.serdes_param_e_RX_CTLE_BW,
                                            sdk.la_mac_port.serdes_param_e_RX_FFE_PRE1_MAX,
                                            sdk.la_mac_port.serdes_param_e_RX_FFE_PRE1_MIN,
                                            sdk.la_mac_port.serdes_param_e_RX_FFE_PRE2_MAX,
                                            sdk.la_mac_port.serdes_param_e_RX_FFE_PRE2_MIN,
                                            sdk.la_mac_port.serdes_param_e_RX_PLL_BB,
                                            sdk.la_mac_port.serdes_param_e_RX_PLL_IFLT,
                                            sdk.la_mac_port.serdes_param_e_RX_PLL_INT,
                                            sdk.la_mac_port.serdes_param_e_RX_NRZ_EYE_THRESHOLD,
                                            sdk.la_mac_port.serdes_param_e_RX_TERM,
                                            sdk.la_mac_port.serdes_param_e_TX_ATTN,
                                            sdk.la_mac_port.serdes_param_e_TX_ATTN_COLD_SIG_ENVELOPE,
                                            sdk.la_mac_port.serdes_param_e_TX_ATTN_HOT_SIG_ENVELOPE,
                                            sdk.la_mac_port.serdes_param_e_TX_PLL_BB,
                                            sdk.la_mac_port.serdes_param_e_TX_PLL_IFLT,
                                            sdk.la_mac_port.serdes_param_e_TX_PLL_INT,
                                            sdk.la_mac_port.serdes_param_e_TX_POST,
                                            sdk.la_mac_port.serdes_param_e_TX_PRE1,
                                            sdk.la_mac_port.serdes_param_e_TX_PRE2,
                                            sdk.la_mac_port.serdes_param_e_TX_PRE3,
                                            sdk.la_mac_port.serdes_param_e_TX_CLK_REFSEL,
                                            sdk.la_mac_port.serdes_param_e_RX_CLK_REFSEL,
                                            sdk.la_mac_port.serdes_param_e_RX_FAST_TUNE]
        mode = sdk.la_mac_port.serdes_param_mode_e_FIXED
        all_serdes_params = []
        for i in range(len(mac_ports)):
            val = i
            serdes_params = [None] * (sdk.la_mac_port.serdes_param_e_LAST + 1)
            for param in self.supported_serdes_params:
                try:
                    for j in range(2):
                        mac_ports[i].set_serdes_parameter(j, stage, param, mode, val)
                    serdes_params[param] = val
                except BaseException as e:
                    self.assertEqual(e.args[0], sdk.la_status_e_E_NOTIMPLEMENTED)

            all_serdes_params.append(serdes_params)

        # Kill the device and reconnect
        rpfo.rpfo(self.uut_device, [], mac_ports)

        # Retrieve the re-created mac_port objects
        mac_ports = self.uut_device.get_objects(sdk.la_object.object_type_e_MAC_PORT)
        self.assertEqual(len(mac_ports), 108)

        # Verify serdes params
        for i in range(len(mac_ports)):
            serdes_params = all_serdes_params[i]
            for param in self.supported_serdes_params:
                try:
                    for j in range(2):
                        mode_out, val_out = mac_ports[i].get_serdes_parameter(j, stage, param)
                        self.assertEqual(mode, mode_out)
                        self.assertEqual(serdes_params[param], val_out)
                except BaseException as e:
                    self.assertEqual(e.args[0], sdk.la_status_e_E_NOTFOUND)
                    self.assertEqual(serdes_params[param], None)

    def verify_pvt_access(self):
        if not self.uut_device.ll_device.is_pacific():
            return
        # If HW device, it takes a few seconds for the voltage and temperature readings to become available.
        if decor.is_hw_device():
            time.sleep(3)

        # ENABLE_SENSOR_POLL==True, PACIFIC_SENSOR_1 should work, PACIFIC_SENSOR_1_DIRECT should fail with E_BUSY
        is_enabled = self.uut_device.device.get_bool_property(sdk.la_device_property_e_ENABLE_SENSOR_POLL)
        self.assertTrue(is_enabled)
        self.verify_temperature_sensor(sdk.la_temperature_sensor_e_PACIFIC_SENSOR_1)

        try:
            dont_care = self.uut_device.device.get_temperature(sdk.la_temperature_sensor_e_PACIFIC_SENSOR_1_DIRECT)
            if decor.is_hw_device():
                self.fail('Direct access to sensor should fail when ENABLE_SENSOR_POLL is True')
        except BaseException as e:
            self.assertEqual(e.args[0], sdk.la_status_e_E_BUSY)

        # ENABLE_SENSOR_POLL==False, both PACIFIC_SENSOR_1 and PACIFIC_SENSOR_1_DIRECT should work
        self.verify_temperature_sensor(sdk.la_temperature_sensor_e_PACIFIC_SENSOR_1)
        self.verify_temperature_sensor(sdk.la_temperature_sensor_e_PACIFIC_SENSOR_1_DIRECT)

    def verify_temperature_sensor(self, sensor):
        low, high = 25, 120
        temperature = self.uut_device.device.get_temperature(sdk.la_temperature_sensor_e_PACIFIC_SENSOR_1)
        self.assertGreaterEqual(temperature, low)
        self.assertLessEqual(temperature, high)


if __name__ == '__main__':
    unittest.main()
