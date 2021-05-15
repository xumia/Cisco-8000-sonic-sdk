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
LA_RATE_UNLIMITED = -1
LA_BURST_DEFAULT = 30
if decor.is_asic5():
    LA_BURST_UNLIMITED = 127
elif decor.is_akpg():
    LA_BURST_UNLIMITED = 31
else:
    LA_BURST_UNLIMITED = 511

LPCS_NUM_OF_GROUPS = 8
START_WEIGHT  = 10


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class logical_port_credit_scheduler(tm_credit_scheduler_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_set_get_logical_port_enable(self):
        slice_id = T.get_device_slice(2)  # valid slice id
        ifg_id = 0   # valid ifg id
        first_serdes_id = T.get_device_first_serdes(0)
        last_serdes_id = T.get_device_first_serdes(1)
        sys_port_gid = 10

        _mac_port = T.mac_port(self, self.device, slice_id, ifg_id, first_serdes_id, last_serdes_id)
        sys_port = T.system_port(self, self.device, sys_port_gid, _mac_port)

        tpcs = sys_port.hld_obj.get_scheduler()
        self.assertNotEqual(tpcs, None)

        tpcs.set_logical_port_enabled(True)
        enabled_status_get = tpcs.get_logical_port_enabled()
        self.assertEqual(enabled_status_get, True)

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_logical_port_credit_scheduler(self):

        slice_id = T.get_device_slice(2)  # valid slice id
        ifg_id = 0   # valid ifg id
        first_serdes_id = 0
        last_serdes_id = 1
        if decor.is_asic5():
            mac_rcfg_serdes_count = 2
        else:
            mac_rcfg_serdes_count = 8
        sys_port_gid = 10

        oid = 300   # valid oid
        oid_inval = 512  # invalid oid
        if decor.is_akpg():
            group_id = 2  # valid group id
        else:
            group_id = 5  # valid group id
        group_id_inval = 8  # invalid group id
        enabled_status = True
        enabled_status_get = False

        weight = 40
        weight_inval = 256  # invalid weight value
        weight_get = 0

        large_cir_rate = 400 * GIGA  # 400 Gbps
        good_cir_rate = 40 * GIGA  # 40 Gbps
        large_pir_rate = 200 * GIGA  # 200 Gbps
        zero_rate = 0 * GIGA  # 0 Gbps
        if decor.is_akpg():
            good_pir_rate = 9 * GIGA  # 10 Gbps
        else:
            good_pir_rate = 45 * GIGA  # 45 Gbps
        default_rate = 959 * GIGA  # default defined rate in register
        if decor.is_asic5():
            mac_recfg_cir_rate = 25 * GIGA
        else:
            mac_recfg_cir_rate = 100 * GIGA

        if decor.is_asic5():
            mac_recfg_eir_rate = 20 * GIGA
        elif decor.is_akpg():
            mac_recfg_eir_rate = 50 * GIGA
        else:
            mac_recfg_eir_rate = 150 * GIGA

        default_burst_size = 30

        rate_get = 0
        rate_inval = 5000 * GIGA  # higher than maximum rate
        acceptable_epsilon = large_cir_rate / 10  # biggest acceptable difference after floating point approximations

        _mac_port = T.mac_port(self, self.device, slice_id, ifg_id, first_serdes_id, last_serdes_id)
        sys_port = T.system_port(self, self.device, sys_port_gid, _mac_port)

        tpcs = sys_port.hld_obj.get_scheduler()
        self.assertNotEqual(tpcs, None)

        try:
            tpcs.get_logical_port_scheduler()
            self.assertFail()
        except sdk.BaseException:
            pass

        tpcs.set_logical_port_enabled(enabled_status)
        lpcs = tpcs.get_logical_port_scheduler()
        self.assertNotEqual(lpcs, None)

        # 2 OQSE of OQPG0-1 are automatically connected to the logical_port
        oq_lst_len = 2
        oq_lst = lpcs.get_attached_oqcs()
        self.assertEqual(oq_lst_len, len(oq_lst))

        oqcs = self.device.create_output_queue_scheduler(slice_id,
                                                         ifg_id, sdk.la_output_queue_scheduler.scheduling_mode_e_DIRECT_4SP)

        # TODO: create an oqcs1 on a different device for negtive test that returns LA_STATUS_EDIFFERENT_DEVS
        #(status, oqcs1) = self.device1.create_output_queue_scheduler(slice_id,
        #                                                             ifg_id, sdk.la_output_queue_scheduler.scheduling_mode_e_DIRECT_4SP)
        #self.assertEqual(status, sdk.la_status_e_SUCCESS)

        try:
            lpcs.attach_oqcs(None, group_id)
            self.assertFail()
        except sdk.BaseException:
            pass

        # TODO: enable after nsim fix for multiple devices
        #status = lpcs.attach_oqcs(oqcs1, group_id)
        #self.assertEqual(status, sdk.la_status_e_E_DIFFERENT_DEVS)

        try:
            lpcs.attach_oqcs(oqcs, group_id_inval)
            self.assertFail()
        except sdk.BaseException:
            pass

        lpcs.attach_oqcs(oqcs, group_id)

        if decor.is_pacific() or decor.is_gibraltar():
            burst_get = lpcs.get_oqcs_eir_or_pir_burst_size(oqcs)
            self.assertEqual(LA_BURST_DEFAULT, burst_get)
            burst_get = 0  # return to pre-test state.

            burst_get = lpcs.get_oqcs_burst_size(oqcs)
            self.assertEqual(LA_BURST_DEFAULT, burst_get)
            burst_get = 0  # return to pre-test state.

        oq_lst_len += 1
        oq_lst = lpcs.get_attached_oqcs()
        self.assertEqual(oq_lst_len, len(oq_lst))
        found = False
        for attached_oqse in oq_lst:
            if oqcs.this == attached_oqse.oqcs.this:
                found = True
                break
        self.assertTrue(found)

        oqcs2 = self.device.create_output_queue_scheduler(
            slice_id, ifg_id, sdk.la_output_queue_scheduler.scheduling_mode_e_DIRECT_4SP)
        lpcs.attach_oqcs(oqcs2, group_id + 1)

        if decor.is_pacific() or decor.is_gibraltar():
            burst_get = lpcs.get_oqcs_eir_or_pir_burst_size(oqcs2)
            self.assertEqual(LA_BURST_DEFAULT, burst_get)
            burst_get = 0  # return to pre-test state.

            burst_get = lpcs.get_oqcs_burst_size(oqcs2)
            self.assertEqual(LA_BURST_DEFAULT, burst_get)
            burst_get = 0  # return to pre-test state.

        oq_lst_len += 1
        oq_lst = lpcs.get_attached_oqcs()
        self.assertEqual(oq_lst_len, len(oq_lst))

        # Detach Oqcs
        with self.assertRaises(sdk.InvalException):
            lpcs.detach_oqcs(None)

        lpcs.detach_oqcs(oqcs2)
        oq_lst_len -= 1
        oq_lst = lpcs.get_attached_oqcs()
        self.assertEqual(oq_lst_len, len(oq_lst))
        found = False
        for attached_oqse in oq_lst:
            if oqcs2.this == attached_oqse.oqcs.this:
                found = True
                break
        self.assertFalse(found)

        with self.assertRaises(sdk.NotFoundException):
            lpcs.detach_oqcs(oqcs2)

        try:
            lpcs.set_group_cir_weight(group_id_inval, weight)
            self.assertFail()
        except sdk.BaseException:
            pass

        try:
            lpcs.get_group_cir_weight(group_id_inval)
            self.assertFail()
        except sdk.BaseException:
            pass

        try:
            lpcs.set_group_cir_weight(group_id, weight_inval)
            self.assertFail()
        except sdk.BaseException:
            pass

        lpcs.set_group_cir_weight(group_id, weight)
        weight_get = lpcs.get_group_cir_weight(group_id)
        self.assertEqual(weight, weight_get)
        weight_get = 0  # return to pre-test state

        try:
            lpcs.set_group_eir_weight(group_id_inval, weight)
            self.assertFail()
        except sdk.BaseException:
            pass

        try:
            lpcs.get_group_eir_weight(group_id_inval)
            self.assertFail()
        except sdk.BaseException:
            pass

        try:
            lpcs.set_group_eir_weight(group_id, weight_inval)
            self.assertFail()
        except sdk.BaseException:
            pass

        lpcs.set_group_eir_weight(group_id, weight)
        weight_get = lpcs.get_group_eir_weight(group_id)
        self.assertEqual(weight, weight_get)
        weight_get = 0  # return to pre-test state

        with self.assertRaises(sdk.InvalException):
            lpcs.set_oqcs_burst_size(None, default_burst_size)

        lpcs.set_oqcs_burst_size(oqcs, default_burst_size)

        try:
            lpcs.set_oqcs_cir(None, large_cir_rate)
            self.assertFail()
        except sdk.BaseException:
            pass

        # TODO: enable after nsim fix for multiple devices
        #status = lpcs.set_oqcs_cir(oqcs1, large_cir_rate)
        #self.assertEqual(status, sdk.la_status_e_E_DIFFERENT_DEVS)

        try:
            lpcs.set_oqcs_cir(oqcs, rate_inval)
            self.assertFail()
        except sdk.BaseException:
            pass

        lpcs.set_oqcs_cir(oqcs, large_cir_rate)

        burst_get = lpcs.get_oqcs_burst_size(oqcs)
        # If scheduler is set to a larger rate than underlying mac_port speed it
        # will be automatically disabled and burst size will be set to LA_BURST_UNLIMITED = 511
        self.assertAlmostEqual(LA_BURST_UNLIMITED, burst_get, delta=acceptable_epsilon)

        burst_get = 0  # return to pre-test state

        try:
            lpcs.get_oqcs_cir(None)
            self.assertFail()
        except sdk.BaseException:
            pass

        # TODO: enable after nsim fix for multiple devices
        #(status, rate_get) = lpcs.get_oqcs_cir(oqcs1)
        #self.assertEqual(status, sdk.la_status_e_E_DIFFERENT_DEVS)
        rate_get = lpcs.get_oqcs_cir(oqcs)
        # If scheduler is set to a larger rate than underlying mac_port speed it
        # will be automatically disabled and return LA_RATE_UNLIMITED == -1
        self.assertAlmostEqual(LA_RATE_UNLIMITED, rate_get, delta=acceptable_epsilon)

        rate_get = 0  # return to pre-test state

        lpcs.set_oqcs_cir(oqcs, good_cir_rate)

        rate_get = lpcs.get_oqcs_cir(oqcs)
        self.assertAlmostEqual(good_cir_rate, rate_get, delta=acceptable_epsilon)

        rate_get = 0  # return to pre-test state

        with self.assertRaises(sdk.InvalException):
            lpcs.get_oqcs_burst_size(None)

        burst_get = lpcs.get_oqcs_burst_size(oqcs)
        self.assertAlmostEqual(default_burst_size, burst_get, delta=acceptable_epsilon)

        burst_get = 0  # return to pre-test state

        # For GB, burst size is set to zero for credit cir zero.
        if decor.is_gibraltar():
            lpcs.set_oqcs_cir(oqcs, zero_rate)
            rate_get = lpcs.get_oqcs_cir(oqcs)
            self.assertAlmostEqual(zero_rate, rate_get, delta=acceptable_epsilon)

            rate_get = 0  # return to pre-test state
            burst_get = lpcs.get_oqcs_burst_size(oqcs)
            self.assertAlmostEqual(0, burst_get, delta=acceptable_epsilon)

            burst_get = 0  # return to pre-test state

        with self.assertRaises(sdk.InvalException):
            lpcs.set_oqcs_eir_or_pir_burst_size(None, default_burst_size)

        lpcs.set_oqcs_eir_or_pir_burst_size(oqcs, default_burst_size)

        try:
            lpcs.set_oqcs_eir_or_pir(None, large_pir_rate, enabled_status)
            self.assertFail()
        except sdk.BaseException:
            pass

        # TODO: enable after nsim fix for multiple devices
        #status = lpcs.set_oqcs_eir_or_pir(oqcs1, large_pir_rate, enabled_status)
        #self.assertEqual(status, sdk.la_status_e_E_DIFFERENT_DEVS)

        try:
            lpcs.set_oqcs_eir_or_pir(oqcs, rate_inval, enabled_status)
            self.assertFail()
        except sdk.BaseException:
            pass

        lpcs.set_oqcs_eir_or_pir(oqcs, large_pir_rate, enabled_status)

        burst_get = lpcs.get_oqcs_eir_or_pir_burst_size(oqcs)
        # If scheduler is set to a larger rate than underlying mac_port speed it
        # will be automatically disabled and burst size will be set to LA_BURST_UNLIMITED = 511
        self.assertAlmostEqual(LA_BURST_UNLIMITED, burst_get, delta=acceptable_epsilon)

        burst_get = 0  # return to pre-test state

        try:
            lpcs.get_oqcs_eir_or_pir(None)
            self.assertFail()
        except sdk.BaseException:
            pass

        # TODO: enable after nsim fix for multiple devices
        #(status, rate_get, enabled_status_get) = lpcs.get_oqcs_eir_or_pir(oqcs1)
        #self.assertEqual(status, sdk.la_status_e_E_DIFFERENT_DEVS)
        (rate_get, enabled_status_get) = lpcs.get_oqcs_eir_or_pir(oqcs)
        self.assertEqual(enabled_status_get, enabled_status)
        # If scheduler is set to a larger rate than underlying mac_port speed it
        # will be automatically disabled and return LA_RATE_UNLIMITED == -1
        self.assertAlmostEqual(LA_RATE_UNLIMITED, rate_get, delta=acceptable_epsilon)

        rate_get = 0  # return to pre-test state

        lpcs.set_oqcs_eir_or_pir(oqcs, good_pir_rate, enabled_status)

        (rate_get, enabled_status_get) = lpcs.get_oqcs_eir_or_pir(oqcs)
        self.assertEqual(enabled_status_get, enabled_status)
        self.assertAlmostEqual(good_pir_rate, rate_get, delta=acceptable_epsilon)

        rate_get = 0  # return to pre-test state
        enabled_status_get = False

        with self.assertRaises(sdk.InvalException):
            lpcs.get_oqcs_eir_or_pir_burst_size(None)

        burst_get = lpcs.get_oqcs_eir_or_pir_burst_size(oqcs)
        self.assertAlmostEqual(default_burst_size, burst_get, delta=acceptable_epsilon)

        burst_get = 0  # return to pre-test state

        # For GB, burst size is set to zero for credit eir/pir zero.
        if decor.is_gibraltar():
            lpcs.set_oqcs_eir_or_pir(oqcs, zero_rate, enabled_status)
            (rate_get, enabled_status_get) = lpcs.get_oqcs_eir_or_pir(oqcs)
            self.assertEqual(enabled_status_get, enabled_status)
            self.assertAlmostEqual(zero_rate, rate_get, delta=acceptable_epsilon)

            rate_get = 0  # return to pre-test state
            burst_get = lpcs.get_oqcs_eir_or_pir_burst_size(oqcs)
            self.assertAlmostEqual(0, burst_get, delta=acceptable_epsilon)

            burst_get = 0  # return to pre-test state

        # Mac port reconfigure related test cases.
        if decor.is_matilda("3.2"):
            # GB 3.2 Does not support mac_port->reconfigure() functionality
            # end the test here
            return
        elif decor.is_asic5():
            _mac_port.hld_obj.reconfigure(mac_rcfg_serdes_count,
                                          sdk.la_mac_port.port_speed_e_E_50G,
                                          sdk.la_mac_port.fc_mode_e_NONE,
                                          sdk.la_mac_port.fc_mode_e_NONE,
                                          sdk.la_mac_port.fec_mode_e_RS_KR4)
        else:
            _mac_port.hld_obj.reconfigure(mac_rcfg_serdes_count,
                                          sdk.la_mac_port.port_speed_e_E_200G,
                                          sdk.la_mac_port.fc_mode_e_NONE,
                                          sdk.la_mac_port.fc_mode_e_NONE,
                                          sdk.la_mac_port.fec_mode_e_RS_KP4)

        lpcs.set_oqcs_cir(oqcs, mac_recfg_cir_rate)
        rate_get = lpcs.get_oqcs_cir(oqcs)
        self.assertAlmostEqual(mac_recfg_cir_rate, rate_get, delta=acceptable_epsilon)
        rate_get = 0  # return to pre-test state.

        lpcs.set_oqcs_burst_size(oqcs, LEGAL_BURST_SIZES[0])
        burst_get = lpcs.get_oqcs_burst_size(oqcs)
        self.assertEqual(LEGAL_BURST_SIZES[0], burst_get)
        burst_get = 0  # return to pre-test state.

        lpcs.set_oqcs_eir_or_pir(oqcs, mac_recfg_eir_rate, enabled_status)
        (rate_get, enabled_status_get) = lpcs.get_oqcs_eir_or_pir(oqcs)
        self.assertEqual(enabled_status_get, enabled_status)
        self.assertAlmostEqual(mac_recfg_eir_rate, rate_get, delta=acceptable_epsilon)
        rate_get = 0  # return to pre-test state.
        enabled_status_get = False

        lpcs.set_oqcs_eir_or_pir_burst_size(oqcs, LEGAL_BURST_SIZES[1])
        burst_get = lpcs.get_oqcs_eir_or_pir_burst_size(oqcs)
        self.assertEqual(LEGAL_BURST_SIZES[1], burst_get)
        burst_get = 0  # return to pre-test state.

        # Reconfigure underlying mac port with 10G speed.
        mac_rcfg_serdes_count = 1
        _mac_port.hld_obj.reconfigure(mac_rcfg_serdes_count,
                                      sdk.la_mac_port.port_speed_e_E_10G,
                                      sdk.la_mac_port.fc_mode_e_NONE,
                                      sdk.la_mac_port.fc_mode_e_NONE,
                                      sdk.la_mac_port.fec_mode_e_KR)

        rate_get = lpcs.get_oqcs_cir(oqcs)
        self.assertAlmostEqual(LA_RATE_UNLIMITED, rate_get, delta=acceptable_epsilon)
        rate_get = 0  # return to pre-test state.

        burst_get = lpcs.get_oqcs_burst_size(oqcs)
        self.assertAlmostEqual(LA_BURST_UNLIMITED, burst_get)
        burst_get = 0  # return to pre-test state.

        (rate_get, enabled_status_get) = lpcs.get_oqcs_eir_or_pir(oqcs)
        self.assertEqual(enabled_status_get, enabled_status)
        self.assertAlmostEqual(LA_RATE_UNLIMITED, rate_get, delta=acceptable_epsilon)
        rate_get = 0  # return to pre-test state.

        burst_get = lpcs.get_oqcs_eir_or_pir_burst_size(oqcs)
        self.assertEqual(LA_BURST_UNLIMITED, burst_get)
        burst_get = 0  # return to pre-test state.

    @unittest.skipIf(decor.is_akpg(), "Test is not yet enabled on akpg")
    def test_group_actual_cir_eir_wfq_weight(self):
        slice_id = T.get_device_slice(2)  # valid slice id
        ifg_id = 0   # valid ifg id
        first_serdes_id = T.get_device_first_serdes(0)
        last_serdes_id = T.get_device_first_serdes(1)
        sys_port_gid = 10

        _mac_port = T.mac_port(self, self.device, slice_id, ifg_id, first_serdes_id, last_serdes_id)
        sys_port = T.system_port(self, self.device, sys_port_gid, _mac_port)

        tpcs = sys_port.hld_obj.get_scheduler()
        self.assertNotEqual(tpcs, None)

        tpcs.set_logical_port_enabled(True)
        lpcs = tpcs.get_logical_port_scheduler()
        self.assertNotEqual(lpcs, None)

        # In Pacific and Gibraltar weights are stored as rates, i.e. 1/weight.
        # SDK calculates new weights after every set_weight and we expect weight(A)/weight(B) ~= rate(B)/rate(A).
        # We allow deviation of 10% due to fitting to HW value (discrete and bounded value).

        # Building array of ciri/eir weights that will try to practice the weight_2_rate algorithm.
        pg_weights = []
        for pg in range(LPCS_NUM_OF_GROUPS):
            pg_weights.append(pg + START_WEIGHT)

        # Set group cir weight.
        for pg in range(LPCS_NUM_OF_GROUPS):
            weight = pg_weights[pg]
            lpcs.set_group_cir_weight(pg, weight)

        # Check get_group_actual_cir_weight.
        pg0_weight = pg_weights[0]
        pg0_rate = lpcs.get_group_actual_cir_weight(0)
        for pg in range(LPCS_NUM_OF_GROUPS):
            pg_rate = lpcs.get_group_actual_cir_weight(pg)
            res = (pg0_weight / pg_weights[pg]) / (pg_rate / pg0_rate)
            self.assertAlmostEqual(res, 1, delta=(0.1))

        # Set group eir weight.
        for pg in range(LPCS_NUM_OF_GROUPS):
            weight = pg_weights[pg]
            lpcs.set_group_eir_weight(pg, weight)

        # Check get_group_actual_cir_weight.
        pg0_weight = pg_weights[0]
        pg0_rate = lpcs.get_group_actual_eir_weight(0)
        for pg in range(LPCS_NUM_OF_GROUPS):
            pg_rate = lpcs.get_group_actual_eir_weight(pg)
            res = (pg0_weight / pg_weights[pg]) / (pg_rate / pg0_rate)
            self.assertAlmostEqual(res, 1, delta=(0.1))


if __name__ == '__main__':
    unittest.main()
