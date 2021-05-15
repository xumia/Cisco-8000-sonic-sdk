# BEGIN_LEGAL
#
# Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
from sdk_test_case_base import *
from leaba import sdk
from packet_test_utils import *
import topology as T
import decor

BYTES_IN_BUF = 384
HBM_BLOCK_GROUP_SIZE = 16

MIRROR_CMD_GID = 0x9

MIRROR_GID_INGRESS_OFFSET = 32
MIRROR_GID_EGRESS_OFFSET = 0
MIRROR_CMD_INGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_INGRESS_OFFSET
MIRROR_CMD_EGRESS_GID = MIRROR_CMD_GID + MIRROR_GID_EGRESS_OFFSET

SLICE = T.get_device_slice(2)
IFG = 0
SP_GID = 0x678
PIF_FIRST = T.get_device_first_serdes(8)
PUNT_INJECT_PORT_MAC_ADDR = "12:34:56:78:9a:bc"
HOST_MAC_ADDR = "fe:dc:ba:98:76:54"
MIRROR_VLAN = 0xA12
SAMPLING_RATE = 0.5
PRIORITY = 1
VOQ_OFFSET = 4


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_device_getters(sdk_test_case_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_get_dependencies(self):
        deps = self.device.get_dependent_objects(self.topology.vrf.hld_obj)
        self.assertNotEqual(len(deps), 0)
        for d in deps:
            self.assertTrue(d.type() == sdk.la_object.object_type_e_L3_AC_PORT or
                            d.type() == sdk.la_object.object_type_e_SVI_PORT)

        count = self.device.get_dependent_objects_count(self.topology.vrf.hld_obj)
        self.assertEqual(len(deps), count)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_get_device(self):
        # Check device ID 1 mapping is valid
        dev1_by_getter = sdk.la_get_device(1)
        self.assertEqual(dev1_by_getter.get_id(), self.device.get_id())

        # Ensure no device is mapped to ID 2
        dev2_by_getter = sdk.la_get_device(2)
        self.assertEqual(dev2_by_getter, None)

        # Ensure out-of-range access returns no device.
        dev_inf_by_getter = sdk.la_get_device(500)
        self.assertEqual(dev_inf_by_getter, None)

    @unittest.skipIf(decor.is_hw_device(), "Unreliable behaviour")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_device_info(self):
        dev_info = self.device.get_device_information()
        self.assertIsNotNone(dev_info)
        if self.device.get_ll_device().is_pacific():
            self.assertIn(dev_info.extension, [0, 1])
        elif self.device.get_ll_device().is_gibraltar():
            self.assertIn(dev_info.extension, [0, 266])

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_get_objects(self):
        objects = self.device.get_objects()
        self.assertNotEqual(len(objects), 0)

    @unittest.skipIf(decor.is_asic5(), "AR-SKIP: AR API changed. Enable once pacific moves to common API")
    @unittest.skipIf(decor.is_asic4(), "PL-SKIP: PL API changed. Enable once pacific moves to common API")
    @unittest.skipIf(decor.is_gibraltar(), "GB-SKIP: GB API changed. Enable once pacific moves to common API")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_cgm_hbm_blocks_by_voq_quantization(self):
        lst = []
        expected_lst = []
        for i in range(0, sdk.LA_CGM_NUM_HBM_BLOCKS_BY_VOQ_QUANTIZATION_CONFIGURABLE_THRESHOLDS):
            lst.append(10 * i)
        thresholds = sdk.la_cgm_hbm_blocks_by_voq_quantization_thresholds()
        thresholds.thresholds = lst

        # Set/get check
        self.device.set_cgm_hbm_blocks_by_voq_quantization(thresholds)
        res_thresholds = self.device.get_cgm_hbm_blocks_by_voq_quantization()
        res_lst = res_thresholds.thresholds
        expected_lst = []
        for i in range(len(lst)):
            expected_lst.append((lst[i] // HBM_BLOCK_GROUP_SIZE) * HBM_BLOCK_GROUP_SIZE)
        self.assertEqual(res_lst, expected_lst)

        # Out-of-range check
        invalid_lst = list(lst)
        invalid_lst[-1] = 1 << 30
        thresholds.thresholds = invalid_lst
        with self.assertRaises(sdk.InvalException):
            self.device.set_cgm_hbm_blocks_by_voq_quantization(thresholds)

    @unittest.skipIf(decor.is_asic5(), "AR-SKIP: AR API changed. Enable once pacific moves to common API")
    @unittest.skipIf(decor.is_asic4(), "PL-SKIP: PL API changed. Enable once pacific moves to common API")
    @unittest.skipIf(decor.is_gibraltar(), "GB-SKIP: GB API changed. Enable once pacific moves to common API")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_cgm_hbm_number_of_voqs_quantization(self):
        lst = []
        expected_lst = []
        for i in range(0, sdk.LA_CGM_NUM_HBM_NUMBER_OF_VOQS_QUANTIZATION_CONFIGURABLE_THRESHOLDS):
            lst.append(10 * i)
        thresholds = sdk.la_cgm_hbm_number_of_voqs_quantization_thresholds()
        thresholds.thresholds = lst

        # Set/get check #1
        self.device.set_cgm_hbm_number_of_voqs_quantization(thresholds)
        res_thresholds = self.device.get_cgm_hbm_number_of_voqs_quantization()
        res_lst = res_thresholds.thresholds
        self.assertEqual(res_lst, lst)

        # Set/get check #2
        lst = []
        expected_lst = []
        for i in range(0, sdk.LA_CGM_NUM_HBM_NUMBER_OF_VOQS_QUANTIZATION_CONFIGURABLE_THRESHOLDS):
            lst.append(10 * (i + 1))
        thresholds = sdk.la_cgm_hbm_number_of_voqs_quantization_thresholds()
        thresholds.thresholds = lst

        self.device.set_cgm_hbm_number_of_voqs_quantization(thresholds)
        res_thresholds = self.device.get_cgm_hbm_number_of_voqs_quantization()
        res_lst = res_thresholds.thresholds
        self.assertEqual(res_lst, lst)

        # Out-of-range check #1
        invalid_lst = list(lst)
        invalid_lst[-1] = 1 << 30
        thresholds.thresholds = invalid_lst
        with self.assertRaises(sdk.InvalException):
            self.device.set_cgm_hbm_number_of_voqs_quantization(thresholds)

        # Out-of-range check #2
        invalid_lst = list(lst)
        invalid_lst[-1] = 4000
        thresholds.thresholds = invalid_lst
        with self.assertRaises(sdk.InvalException):
            self.device.set_cgm_hbm_number_of_voqs_quantization(thresholds)

        # Out-of-range check #3
        invalid_lst = list(lst)
        invalid_lst[-1] = -1
        thresholds.thresholds = invalid_lst
        with self.assertRaises(sdk.InvalException):
            self.device.set_cgm_hbm_number_of_voqs_quantization(thresholds)

    @unittest.skipIf(decor.is_asic5(), "AR-SKIP: AR API changed. Enable once pacific moves to common API")
    @unittest.skipIf(decor.is_asic4(), "PL-SKIP: PL API changed. Enable once pacific moves to common API")
    @unittest.skipIf(decor.is_gibraltar(), "GB-SKIP: GB API changed. Enable once pacific moves to common API")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_cgm_hbm_pool_free_blocks_quantization(self):
        lst = []
        expected_lst = []
        for i in range(0, sdk.LA_CGM_NUM_HBM_POOL_FREE_BLOCKS_QUANTIZATION_CONFIGURABLE_THRESHOLDS):
            lst.append(10 * i)
        thresholds = sdk.la_cgm_hbm_pool_free_blocks_quantization_thresholds()
        thresholds.thresholds = lst

        # Set/get check
        self.device.set_cgm_hbm_pool_free_blocks_quantization(0, thresholds)
        (res_thresholds) = self.device.get_cgm_hbm_pool_free_blocks_quantization(0)
        res_lst = res_thresholds.thresholds
        expected_lst = []
        for i in range(len(lst)):
            expected_lst.append((lst[i] // HBM_BLOCK_GROUP_SIZE) * HBM_BLOCK_GROUP_SIZE)
        self.assertEqual(res_lst, expected_lst)

        # Monotone check
        invalid_lst = list(lst)
        invalid_lst[-1] = 0
        thresholds.thresholds = invalid_lst
        with self.assertRaises(sdk.InvalException):
            self.device.set_cgm_hbm_pool_free_blocks_quantization(0, thresholds)

        # Out-of-range check
        invalid_lst[-1] = 1 << 30
        thresholds.thresholds = invalid_lst
        with self.assertRaises(sdk.InvalException):
            self.device.set_cgm_hbm_pool_free_blocks_quantization(0, thresholds)

        thresholds.thresholds = lst
        hbm_pool = 2
        with self.assertRaises(sdk.InvalException):
            self.device.set_cgm_hbm_pool_free_blocks_quantization(hbm_pool, thresholds)

    @unittest.skipIf(decor.is_asic4(), "PL-SKIP: PL API changed. Enable once pacific moves to common API")
    @unittest.skipIf(decor.is_asic5(), "AR-SKIP: AR API changed. Enable once pacific moves to common API")
    @unittest.skipIf(decor.is_gibraltar(), "GB-SKIP: GB API changed. Enable once pacific moves to common API")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_cgm_sms_voqs_bytes_quantization(self):
        lst = []
        expected_lst = []
        for i in range(0, sdk.LA_CGM_NUM_SMS_BYTES_QUANTIZATION_CONFIGURABLE_THRESHOLDS):
            lst.append(100 * i)
            expected_lst.append(int(round(lst[i] / BYTES_IN_BUF) * BYTES_IN_BUF))
        thresholds = sdk.la_cgm_sms_bytes_quantization_thresholds()
        thresholds.thresholds = lst

        # Set/get check
        self.device.set_cgm_sms_voqs_bytes_quantization(thresholds)
        res_thresholds = self.device.get_cgm_sms_voqs_bytes_quantization()
        res_lst = res_thresholds.thresholds
        self.assertEqual(expected_lst, res_lst)

        # Monotone check
        invalid_lst = list(lst)
        invalid_lst[-1] = 0
        thresholds.thresholds = invalid_lst
        with self.assertRaises(sdk.InvalException):
            self.device.set_cgm_sms_voqs_bytes_quantization(thresholds)

        # Out-of-range check
        invalid_lst[-1] = 1 << 30
        thresholds.thresholds = invalid_lst
        with self.assertRaises(sdk.InvalException):
            self.device.set_cgm_sms_voqs_bytes_quantization(thresholds)

    @unittest.skipIf(decor.is_asic4(), "PL-SKIP: PL API changed. Enable once pacific moves to common API")
    @unittest.skipIf(decor.is_asic5(), "AR-SKIP: AR API changed. Enable once pacific moves to common API")
    @unittest.skipIf(decor.is_gibraltar(), "GB-SKIP: GB API changed. Enable once pacific moves to common API")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_cgm_sms_voqs_packets_quantization(self):
        lst = []
        expected_lst = []
        for i in range(0, sdk.LA_CGM_NUM_SMS_PACKETS_QUANTIZATION_CONFIGURABLE_THRESHOLDS):
            lst.append(10 * i)
        thresholds = sdk.la_cgm_sms_packets_quantization_thresholds()
        thresholds.thresholds = lst

        # Set/get check
        self.device.set_cgm_sms_voqs_packets_quantization(thresholds)
        res_thresholds = self.device.get_cgm_sms_voqs_packets_quantization()
        res_lst = res_thresholds.thresholds
        self.assertEqual(res_lst, lst)

        # Monotone check
        invalid_lst = list(lst)
        invalid_lst[-1] = 0
        thresholds.thresholds = invalid_lst
        with self.assertRaises(sdk.InvalException):
            self.device.set_cgm_sms_voqs_packets_quantization(thresholds)

        # Out-of-range check
        invalid_lst[-1] = 1 << 30
        thresholds.thresholds = invalid_lst
        with self.assertRaises(sdk.InvalException):
            self.device.set_cgm_sms_voqs_packets_quantization(thresholds)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_snoop_configuration(self):
        pi_port = T.punt_inject_port(
            self,
            self.device,
            SLICE,
            IFG,
            SP_GID,
            PIF_FIRST,
            PUNT_INJECT_PORT_MAC_ADDR)

        mirror_cmd = T.create_l2_mirror_command(
            self.device,
            MIRROR_CMD_EGRESS_GID,
            pi_port,
            HOST_MAC_ADDR,
            MIRROR_VLAN,
            SAMPLING_RATE,
            VOQ_OFFSET)
        voq_offset = mirror_cmd.get_voq_offset()
        self.assertEqual(voq_offset, VOQ_OFFSET)

        self.device.clear_trap_configuration(sdk.LA_EVENT_L3_INGRESS_MONITOR)
        self.device.set_snoop_configuration(sdk.LA_EVENT_L3_INGRESS_MONITOR, PRIORITY, False, False, mirror_cmd)

        (res_priority, res_mirror_cmd) = self.device.get_snoop_configuration(sdk.LA_EVENT_L3_INGRESS_MONITOR)

        # Comparison
        self.assertEqual(res_priority, PRIORITY)
        self.assertEqual(res_mirror_cmd.get_gid(), MIRROR_CMD_EGRESS_GID)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_sms_buffer_getter(self):
        for slice_id in self.device.get_used_slices():
            for ifg in range(T.NUM_IFGS_PER_SLICE):
                sms_packets_count = self.device.get_sms_total_packet_counts(slice_id,
                                                                            ifg,
                                                                            False)
                self.assertIsNotNone(sms_packets_count)
        sms_errors = self.device.get_sms_error_counts(False)
        self.assertIsNotNone(sms_errors)

        sms_free_buffers = self.device.get_sms_total_free_buffer_summary(False)
        self.assertIsNotNone(sms_free_buffers)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_cgm_watermarks_getter(self):
        cgm_watermarks = self.device.get_cgm_watermarks()
        self.assertIsNotNone(cgm_watermarks)

    @unittest.skipUnless(decor.is_gibraltar(), "Only implemented for Gibraltar")
    def test_component_health_getter(self):
        comp_health = self.device.get_component_health()
        self.assertIsNotNone(comp_health)


if __name__ == '__main__':
    unittest.main()
