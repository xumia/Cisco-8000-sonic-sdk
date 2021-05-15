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
from leaba import sdk
import decor
import time

verbose = 0


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_temperature_sensor(unittest.TestCase):

    def setUp(self):
        dev_id = 0
        if verbose >= 1:
            sdk.la_set_logging_level(dev_id, sdk.la_logger_component_e_PVT, sdk.la_logger_level_e_DEBUG)
        if verbose >= 2:
            sdk.la_set_logging_level(dev_id, sdk.la_logger_component_e_CPU2JTAG, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_level(dev_id, sdk.la_logger_component_e_HLD, sdk.la_logger_level_e_DEBUG)
        import sim_utils
        self.device = sim_utils.create_device(dev_id)

    def tearDown(self):
        self.device.tearDown()

    def test_dispatch(self):
        if self.device.get_ll_device().is_gibraltar():
            self.do_test_gibraltar_sensors()
        elif self.device.get_ll_device().is_asic4():
            self.do_test_asic4_sensors()
        elif self.device.get_ll_device().is_asic5():
            self.do_test_asic5_sensors()
        elif self.device.get_ll_device().is_asic3():
            self.do_test_asic3_sensors()
        else:
            self.do_test_pacific_sensors()

    def do_test_pacific_sensors(self):
        # On Pacific, wait for non-direct temperature and voltage sensors to become available
        temperature_sensors = [sdk.la_temperature_sensor_e_PACIFIC_SENSOR_1,
                               sdk.la_temperature_sensor_e_PACIFIC_SENSOR_2]
        temperature_direct_sensors = [sdk.la_temperature_sensor_e_PACIFIC_SENSOR_1_DIRECT,
                                      sdk.la_temperature_sensor_e_PACIFIC_SENSOR_2_DIRECT]
        voltage_sensors = [sdk.la_voltage_sensor_e_PACIFIC_SENSOR_1_VDD,
                           sdk.la_voltage_sensor_e_PACIFIC_SENSOR_1_AVDD,
                           sdk.la_voltage_sensor_e_PACIFIC_SENSOR_2_VDD,
                           sdk.la_voltage_sensor_e_PACIFIC_SENSOR_2_AVDD]

        self.do_wait_for_sensors(temperature_sensors, voltage_sensors)

        low, high = (20, 120) if decor.is_hw_device() else (35, 35)
        self.do_test_sensors('temperature', temperature_sensors, low, high)

        # On Pacific, when polling is enabled, direct sensors should return back E_BUSY
        for sensor in temperature_direct_sensors:
            try:
                val = self.device.get_temperature(sensor)
            except BaseException as status:
                self.assertEqual(status.args[0], sdk.la_status_e_E_BUSY)

        low, high = (0.7, 1.5) if decor.is_hw_device() else (1.0, 1.0)
        self.do_test_sensors('voltage', voltage_sensors, low, high)

    def do_test_gibraltar_sensors(self):
        # On GB, wait for RXPP_0 temperature sensor and RXPP_0 voltage sensor to become available
        self.do_wait_for_sensors([sdk.la_temperature_sensor_e_GIBRALTAR_SENSOR_0],
                                 [sdk.la_voltage_sensor_e_GIBRALTAR_SENSOR_0])

        hbm_enabled = self.device.get_bool_property(sdk.la_device_property_e_ENABLE_HBM)
        if hbm_enabled:
            sensors = range(sdk.la_temperature_sensor_e_GIBRALTAR_FIRST,
                            sdk.la_temperature_sensor_e_GIBRALTAR_LAST + 1)
        else:
            sensors = range(sdk.la_temperature_sensor_e_GIBRALTAR_FIRST,
                            sdk.la_temperature_sensor_e_GIBRALTAR_SENSOR_9 + 1)

        low, high = (20, 120) if decor.is_hw_device() else (35, 35)

        self.do_test_sensors('temperature', sensors, low, high)

        sensors = range(sdk.la_voltage_sensor_e_GIBRALTAR_FIRST, sdk.la_voltage_sensor_e_GIBRALTAR_LAST + 1)
        low, high = (0.7, 1.0) if decor.is_hw_device() else (1.0, 1.0)

        self.do_test_sensors('voltage', sensors, low, high)

    def do_test_asic4_sensors(self):
        # On PL, wait for RXPP_0 temperature sensor and RXPP_0 voltage sensor to become available
        self.do_wait_for_sensors([sdk.la_temperature_sensor_e_ASIC4_SENSOR_0],
                                 [sdk.la_voltage_sensor_e_ASIC4_SENSOR_0])

        hbm_enabled = self.device.get_bool_property(sdk.la_device_property_e_ENABLE_HBM)
        if hbm_enabled:
            sensors = range(sdk.la_temperature_sensor_e_ASIC4_FIRST,
                            sdk.la_temperature_sensor_e_ASIC4_LAST + 1)
        else:
            sensors = range(sdk.la_temperature_sensor_e_ASIC4_FIRST,
                            sdk.la_temperature_sensor_e_ASIC4_SENSOR_9 + 1)

        low, high = (20, 120) if decor.is_hw_device() else (35, 35)

        self.do_test_sensors('temperature', sensors, low, high)

        sensors = range(sdk.la_voltage_sensor_e_ASIC4_FIRST, sdk.la_voltage_sensor_e_ASIC4_LAST + 1)
        low, high = (0.7, 1.0) if decor.is_hw_device() else (1.0, 1.0)

        self.do_test_sensors('voltage', sensors, low, high)

    def do_test_asic5_sensors(self):
        # On AR, wait for RXPP_0 temperature sensor and RXPP_0 voltage sensor to become available
        self.do_wait_for_sensors([sdk.la_temperature_sensor_e_ASIC5_SENSOR_0],
                                 [sdk.la_voltage_sensor_e_ASIC5_SENSOR_0])

        sensors = range(sdk.la_temperature_sensor_e_ASIC5_FIRST,
                        sdk.la_temperature_sensor_e_ASIC5_LAST + 1)

        low, high = (20, 120) if decor.is_hw_device() else (35, 35)

        self.do_test_sensors('temperature', sensors, low, high)

        sensors = range(sdk.la_voltage_sensor_e_ASIC5_FIRST, sdk.la_voltage_sensor_e_ASIC5_LAST + 1)
        low, high = (0.7, 1.0) if decor.is_hw_device() else (1.0, 1.0)

        self.do_test_sensors('voltage', sensors, low, high)

    def do_test_asic3_sensors(self):
        # On GR, wait for all sensors to be ready
        self.do_wait_for_sensors([sdk.la_temperature_sensor_e_ASIC3_LAST],
                                 [sdk.la_voltage_sensor_e_ASIC3_LAST])

        sensors = range(sdk.la_temperature_sensor_e_ASIC3_FIRST,
                        sdk.la_temperature_sensor_e_ASIC3_LAST + 1)

        low, high = (20, 120) if decor.is_hw_device() else (35, 35)

        self.do_test_sensors('temperature', sensors, low, high)

        sensors = range(sdk.la_voltage_sensor_e_ASIC3_FIRST,
                        sdk.la_voltage_sensor_e_ASIC3_LAST + 1)

        low, high = (0.7, 1.0) if decor.is_hw_device() else (1.0, 1.0)

        self.do_test_sensors('voltage', sensors, low, high)

    def do_test_sensors(self, sensor_type, sensors, low, high):
        # Read voltage or temperature sensors one by one
        for sensor in sensors:
            if sensor_type is 'voltage':
                val = self.device.get_voltage(sensor)
            else:
                val = self.device.get_temperature(sensor)
            self.assertGreaterEqual(val, low, "%s sensor=%d" % (sensor_type, sensor))
            self.assertLessEqual(val, high, "%s sensor=%d" % (sensor_type, sensor))

    def do_wait_for_sensors(self, temperature_sensors, voltage_sensors):
        # Wait for temperature and voltage sensors to become available.
        #
        # If HW device, it takes a few seconds for the voltage and temperature readings to become available.
        # If simulated device, the polling below iterates only once.
        if decor.is_hw_device():
            time.sleep(3)

        temperature, voltage = None, None
        for i in range(10):
            try:
                for sensor in temperature_sensors:
                    temperature = self.device.get_temperature(sensor)
                for sensor in voltage_sensors:
                    voltage = self.device.get_voltage(sensor)
                break
            except sdk.BaseException as status:
                temperature, voltage = None, None
                if verbose >= 1:
                    print('sensors are not ready, retry=%d' % i)
            time.sleep(0.5)

        self.assertIsNotNone(temperature, "temperature sensors are not ready")
        self.assertIsNotNone(voltage, "voltage sensors are not ready")


if __name__ == '__main__':
    unittest.main()
