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

import decor
import unittest
from leaba import sdk
import sim_utils
import topology as T
from tm_credit_scheduler_base import *

KILO = 1000
MEGA = 1000 * KILO
GIGA = 1000 * MEGA

MIN_TM_RATE = 588 * MEGA
OQCS_NUM_OF_GROUPS = 4

ARBITRARY_VALUE = 10


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class out_queue_credit_scheduler(tm_credit_scheduler_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic5(), "Test is not applicable to AR")
    @unittest.skipIf(decor.is_matilda(),
                     "Matilda does not support Linecard and Fabric modes. Irrelevant test.")
    def test_out_queue_credit_scheduler(self):
        slice_id = 2  # valid slice id
        fabric_slice_id = 4  # fabric slice id
        ifg_id = 0   # valid ifg id
        first_serdes_id = 4
        last_serdes_id = 5
        sys_port_gid = 10

        oid = 6   # Number of Output Queue per TM port CS [0-7]
        oid_inval = 8  # invalid oid
        group_id = 3  # valid group id
        group_id_inval = 8  # invalid group id

        weight = 150  # Valid WFQ range is [1-255]
        weight_inval = 256  # invalid weight value
        weight_get = 0

        rate = 400 * GIGA  # 400 Gbps
        rate_get = 0
        acceptable_epsilon = rate / 10  # biggest acceptable difference after floating point approximations

        vsc = 1233  # [0-20479]
        vsc_inval = 20480
        ingress_device = 76
        ingress_slice = 2
        ingress_voq_id = 200
        masking_epsilon = (1 << 4) - 1  # biggest difference after 4 bit masking

        cs = self.device.get_ifg_scheduler(slice_id, ifg_id)
        self.assertNotEqual(cs, None)

        _mac_port = T.mac_port(self, self.device, slice_id, ifg_id, first_serdes_id, last_serdes_id)
        sys_port = T.system_port(self, self.device, sys_port_gid, _mac_port)

        tpcs = sys_port.hld_obj.get_scheduler()
        self.assertNotEqual(tpcs, None)

        try:
            tpcs.get_output_queue_scheduler(oid_inval)
            self.assertFail()
        except sdk.BaseException:
            pass

        oqcs = tpcs.get_output_queue_scheduler(oid)
        self.assertNotEqual(oqcs, None)

        oqcs.set_scheduling_mode(sdk.la_output_queue_scheduler.scheduling_mode_e_DIRECT_4SP)

        # WFQ checks
        try:
            oqcs.set_group_weight(group_id_inval, weight)
            self.assertFail()
        except sdk.BaseException:
            pass

        try:
            oqcs.set_group_weight(group_id, weight_inval)
            self.assertFail()
        except sdk.BaseException:
            pass

        local_device_id = self.device.get_id()  # for fabric slice ingress device is local

        out_vsc_vector = oqcs.get_attached_vscs()
        vsc_vector_len = len(out_vsc_vector)

        if decor.is_asic4():
            oqcs.attach_vsc(vsc, sdk.la_oq_vsc_mapping_e_RR0, ingress_device, ingress_slice, ingress_voq_id)
        else:
            oqcs.attach_vsc(vsc, sdk.la_oq_vsc_mapping_e_RR3, ingress_device, ingress_slice, ingress_voq_id)
        vsc_vector_len += 1
        out_vsc_vector = oqcs.get_attached_vscs()
        self.assertEqual(len(out_vsc_vector), vsc_vector_len)

        # different values
        oqcs.attach_vsc(vsc + 1, sdk.la_oq_vsc_mapping_e_RR2, local_device_id, fabric_slice_id, ingress_voq_id + 1)
        out_vsc_vector = oqcs.get_attached_vscs()
        vsc_vector_len += 1
        self.assertEqual(len(out_vsc_vector), vsc_vector_len)

        if decor.is_akpg():
            for vsc_elem in out_vsc_vector:
                if vsc_elem.vsc == vsc + 1:
                    self.assertEqual(vsc_elem.map, sdk.la_oq_vsc_mapping_e_RR2)
                    self.assertEqual(vsc_elem.device_id, local_device_id)
                    self.assertEqual(vsc_elem.slice_id, fabric_slice_id)
                    #self.assertAlmostEqual(out_vsc_vector[6].voq_id, ingress_voq_id + 1, delta=masking_epsilon)
        else:
            self.assertEqual(out_vsc_vector[7].vsc, vsc + 1)
            self.assertEqual(out_vsc_vector[7].map, sdk.la_oq_vsc_mapping_e_RR2)
            self.assertEqual(out_vsc_vector[7].device_id, local_device_id)
            self.assertEqual(out_vsc_vector[7].slice_id, fabric_slice_id)
            self.assertAlmostEqual(out_vsc_vector[6].voq_id, ingress_voq_id + 1, delta=masking_epsilon)

        oqcs.detach_vsc(vsc + 1)
        out_vsc_vector = oqcs.get_attached_vscs()
        vsc_vector_len -= 1
        self.assertEqual(len(out_vsc_vector), vsc_vector_len)
        self.assertFalse(any((out_vsc.vsc == vsc + 1) for out_vsc in out_vsc_vector))

        with self.assertRaises(sdk.NotFoundException):
            oqcs.detach_vsc(vsc + 1)

        try:
            oqcs.set_vsc_pir(vsc_inval, rate)
            self.assertFail()
        except sdk.BaseException:
            pass

        oqcs.set_vsc_pir(vsc, rate)
        rate_get = oqcs.get_vsc_pir(vsc)
        self.assertAlmostEqual(rate, rate_get, delta=acceptable_epsilon)

        # burst_size checks
        try:
            oqcs.set_vsc_burst_size(vsc, OVERSIZE_BURST_SIZE)
            self.assertFail()
        except sdk.BaseException:
            pass

        for bucket_size in LEGAL_BURST_SIZES:
            oqcs.set_vsc_burst_size(vsc, bucket_size)
            res_bucket_size = oqcs.get_vsc_burst_size(vsc)
            self.assertEqual(res_bucket_size, bucket_size)

        # 0 locks the shaper due to bug in the Pacific
        oqcs.set_vsc_burst_size(vsc, 0)
        res_bucket_size = oqcs.get_vsc_burst_size(vsc)
        self.assertEqual(res_bucket_size, 0)

        try:
            oqcs.set_vsc_burst_size(vsc, LEGAL_BURST_SIZES[0])
            self.assertFail()
        except BaseException:
            pass

        rate_get = 0  # return to pre-test state

    def check_wfq_getters(self, oqcs):
        # Building array of weights that will try to practice the weight_2_rate algorithm.
        pg_weights = []
        for pg in range(OQCS_NUM_OF_GROUPS):
            pg_weights.append(pg + ARBITRARY_VALUE)

        # Check set/get weight.
        for pg in range(OQCS_NUM_OF_GROUPS):
            weight = pg_weights[pg]
            oqcs.set_group_weight(pg, weight)
            weight_get = oqcs.get_group_weight(pg)
            self.assertEqual(weight_get, weight)

        with self.assertRaises(sdk.InvalException):
            oqcs.set_group_weight(OQCS_NUM_OF_GROUPS, 1)

        # Check get_actual weight.
        # In Pacific weights are stored as rates, i.e. 1/weight.
        # SDK calculates new weights after every set_weight and we expect weight(A)/weight(B) ~= rate(B)/rate(A).
        # We allow deviation of 10% due to fitting to HW value (discrete and bounded value).
        pg0_weight = pg_weights[0]
        pg0_rate = oqcs.get_group_actual_weight(0)
        for pg in range(OQCS_NUM_OF_GROUPS):
            pg_rate = oqcs.get_group_actual_weight(pg)
            res = (pg0_weight / pg_weights[pg]) / (pg_rate / pg0_rate)
            self.assertAlmostEqual(res, 1, delta=(0.1))

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_default_vsc_oqse_mapping_CSCvw03429(self):
        slice_id = T.get_device_slice(2)
        ifg_id = 0
        first_serdes_id = T.get_device_first_serdes(0)
        last_serdes_id = T.get_device_last_serdes(1)
        sys_port_gid = 10

        cs = self.device.get_ifg_scheduler(slice_id, ifg_id)
        self.assertNotEqual(cs, None)

        _mac_port = T.mac_port(self, self.device, slice_id, ifg_id, first_serdes_id, last_serdes_id)
        sys_port = T.system_port(self, self.device, sys_port_gid, _mac_port)

        tpcs = sys_port.hld_obj.get_scheduler()
        self.assertNotEqual(tpcs, None)

        oqcs = tpcs.get_output_queue_scheduler(0)
        vsc_lst = oqcs.get_attached_vscs()
        used_slices = self.device.get_used_slices()
        self.assertEqual(len(vsc_lst), len(used_slices))


if __name__ == '__main__':
    unittest.main()
