#!/usr/bin/env python3
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


from packet_test_utils import *
import unittest
from leaba import sdk
import sim_utils
import topology as T
from sdk_test_case_base import *
import decor

BASE_VOQ_ID = 250
SET_SIZE = 2
DEST_SLICE = 0
DEST_IFG = T.get_device_ifg(1)

VSC_SLICE_STEP = 16
VSC_DEVICE_STEP = T.NETWORK_SLICES * VSC_SLICE_STEP

FIRST_SERDES = 0
SYS_PORT_GID = 0x500


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_voq_set(sdk_test_case_base):

    def setUp(self):
        super().setUp(create_default_topology=False)

        self.dest_device = self.device.get_id()

        self.first_vsc = self.device.get_limit(sdk.limit_type_e_DEVICE__MIN_ALLOCATABLE_VSC)
        base_vsc_vec = []
        for slice_id in range(T.NETWORK_SLICES):
            base_vsc_vec.append(self.first_vsc + slice_id * VSC_SLICE_STEP)
        self.voq_set = self.device.create_voq_set(BASE_VOQ_ID, SET_SIZE, base_vsc_vec, self.dest_device, DEST_SLICE, DEST_IFG)

        # Attach a counter
        self.counter = self.device.create_counter(2)
        self.voq_set.set_counter(sdk.la_voq_set.voq_counter_type_e_BOTH, 2, self.counter)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_busy_voq(self):
        base_voq = BASE_VOQ_ID + 1
        base_vsc_vec = []
        for slice_id in range(T.NETWORK_SLICES):
            base_vsc_vec.append(self.first_vsc + SET_SIZE + slice_id * VSC_SLICE_STEP)

        try:
            self.device.create_voq_set(base_voq, SET_SIZE, base_vsc_vec, self.dest_device, DEST_SLICE, DEST_IFG)
            self.assertFail()
        except sdk.BaseException:
            pass

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_busy_vsc(self):
        base_voq = BASE_VOQ_ID + SET_SIZE
        base_vsc_vec = []
        for slice_id in range(T.NETWORK_SLICES):
            base_vsc_vec.append(self.first_vsc + slice_id * VSC_SLICE_STEP)

        try:
            self.device.create_voq_set(base_voq, SET_SIZE, base_vsc_vec, self.dest_device, DEST_SLICE, DEST_IFG)
            self.assertFail()
        except sdk.BaseException:
            pass

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_crossing_native_set(self):
        base_voq = 15
        base_vsc_vec = []
        for slice_id in range(T.NETWORK_SLICES):
            base_vsc_vec.append(self.first_vsc + VSC_DEVICE_STEP + slice_id * VSC_SLICE_STEP)

        try:
            self.device.create_voq_set(base_voq, SET_SIZE, base_vsc_vec, self.dest_device, DEST_SLICE, DEST_IFG)
            self.assertFail()
        except sdk.BaseException:
            pass

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_invalid_slice_ifg(self):
        base_voq = BASE_VOQ_ID + 16
        base_vsc_vec = []
        for slice_id in range(T.NETWORK_SLICES):
            base_vsc_vec.append(self.first_vsc + SET_SIZE + slice_id * VSC_SLICE_STEP)

        try:
            self.device.create_voq_set(base_voq, SET_SIZE, base_vsc_vec, self.dest_device, 6, DEST_IFG)
            self.assertFail()
        except sdk.BaseException:
            pass

        try:
            self.device.create_voq_set(base_voq, SET_SIZE, base_vsc_vec, self.dest_device, DEST_SLICE, 2)
            self.assertFail()
        except sdk.BaseException:
            pass

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_set_cgm_profile(self):

        mac_port = self.device.create_mac_port(
            DEST_SLICE,
            DEST_IFG,
            FIRST_SERDES,
            FIRST_SERDES + 1,
            sdk.la_mac_port.port_speed_e_E_50G,
            sdk.la_mac_port.fc_mode_e_NONE,
            sdk.la_mac_port.fec_mode_e_RS_KR4)
        try:
            sys_port = self.device.create_system_port(SYS_PORT_GID, mac_port, self.voq_set, self.topology.tc_profile_def.hld_obj)
            self.assertFail()
        except sdk.BaseException:
            pass

        voq_cgm_profile = self.device.create_voq_cgm_profile()

        for voq in range(SET_SIZE):
            self.voq_set.set_cgm_profile(voq, voq_cgm_profile)

        sys_port = self.device.create_system_port(SYS_PORT_GID, mac_port, self.voq_set, self.topology.tc_profile_def.hld_obj)

        try:
            self.device.destroy(voq_cgm_profile)
            self.assertFail()
        except sdk.BaseException:
            pass

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_two_sets_on_single_native_set(self):
        base_voq = BASE_VOQ_ID + 16
        base_vsc_vec = []
        for slice_id in range(T.NETWORK_SLICES):
            base_vsc_vec.append(self.first_vsc + SET_SIZE + slice_id * VSC_SLICE_STEP)
        voq_set_2 = self.device.create_voq_set(base_voq, SET_SIZE, base_vsc_vec, self.dest_device, DEST_SLICE, DEST_IFG)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_voq_counter(self):
        base_voq = BASE_VOQ_ID + 16
        base_vsc_vec = []
        for slice_id in range(T.NETWORK_SLICES):
            base_vsc_vec.append(self.first_vsc + SET_SIZE + slice_id * VSC_SLICE_STEP)
        voq_set_2 = self.device.create_voq_set(base_voq, SET_SIZE, base_vsc_vec, self.dest_device, DEST_SLICE, DEST_IFG)

        # Attach a counter
        counter_2 = self.device.create_counter(2)
        voq_set_2.set_counter(sdk.la_voq_set.voq_counter_type_e_BOTH, 2, counter_2)

        # Getter test
        (res_voq_counter_type, res_group_size, res_counter) = voq_set_2.get_counter()
        self.assertEqual(res_voq_counter_type, sdk.la_voq_set.voq_counter_type_e_BOTH)
        self.assertEqual(res_group_size, 2)
        self.assertEqual(res_counter.this, counter_2.this)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_wrong_slice_ifg(self):
        base_voq = BASE_VOQ_ID + SET_SIZE
        base_vsc_vec = []
        for slice_id in range(T.NETWORK_SLICES):
            base_vsc_vec.append(self.first_vsc + VSC_DEVICE_STEP + slice_id * VSC_SLICE_STEP)

        try:
            self.device.create_voq_set(base_voq, SET_SIZE, base_vsc_vec, self.dest_device, DEST_SLICE + 1, DEST_IFG)
            self.assertFail()
        except sdk.BaseException:
            pass

        try:
            self.device.create_voq_set(base_voq, SET_SIZE, base_vsc_vec, self.dest_device, DEST_SLICE, 1 - DEST_IFG)
            self.assertFail()
        except sdk.BaseException:
            pass

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_wrong_voq_counter(self):
        base_voq = BASE_VOQ_ID + 16
        base_vsc_vec = []
        for slice_id in range(T.NETWORK_SLICES):
            base_vsc_vec.append(self.first_vsc + SET_SIZE + slice_id * VSC_SLICE_STEP)
        voq_set_2 = self.device.create_voq_set(base_voq, SET_SIZE, base_vsc_vec, self.dest_device, DEST_SLICE, DEST_IFG)

        # Attach a counter
        counter_2 = self.device.create_counter(4)

        try:
            voq_set_2.set_counter(sdk.la_voq_set.voq_counter_type_e_BOTH, 4, counter_2)
        except sdk.BaseException as STATUS:
            self.assertEqual(STATUS.args[0], sdk.la_status_e_E_INVAL)

        try:
            voq_set_2.set_counter(sdk.la_voq_set.voq_counter_type_e_ENQUEUED, 4, counter_2)
        except sdk.BaseException as STATUS:
            self.assertEqual(STATUS.args[0], sdk.la_status_e_E_NOTIMPLEMENTED)


if __name__ == '__main__':
    unittest.main()
