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

import unittest
from leaba import sdk
import decor
import topology as T
from tm_transmit_scheduler_base import *

LA_RATE_UNLIMITED = -1
LA_BURST_UNLIMITED = 511
OQ_COUNT = 8
if decor.is_asic5():
    SERDES_COUNT = 2
elif decor.is_akpg():
    SERDES_COUNT = 4
else:
    SERDES_COUNT = 8


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class system_port_transmit_scheduler(tm_transmit_scheduler_base):

    def test_system_port_transmit_scheduler(self):
        slice_id = T.get_device_slice(2)  # valid slice id
        ifg_id = 0   # valid ifg id
        first_serdes_id = 0
        last_serdes_id = 1
        mac_rcfg_serdes_count = SERDES_COUNT
        sys_port_gid = 10

        oid = 4   # valid oid
        pg = sdk.la_system_port_scheduler.priority_group_e_SP6
        large_cir_rate = 401500 * MEGA  # 400 Gbps
        good_cir_rate = 40 * GIGA  # 40 Gbps
        large_pir_rate = 200262 * MEGA  # 200 Gbps
        zero_rate = 0 * GIGA  # 0 Gbps
        akpg_pir_rate = 608000 * MEGA    # ratio used so need nice math
        good_pir_rate = 45 * GIGA  # 45 Gbps
        full_cir_rate = 950 * GIGA  # DEFAULT_RATE_GBPS
        full_pir_rate = 950 * GIGA  # DEFAULT_RATE_GBPS
        mac_recfg_rate = 10 * GIGA
        if decor.is_asic5():
            mac_recfg_pir_rate = 25 * GIGA
            mac_recfg_pg_rate = 45 * GIGA
        else:
            mac_recfg_pir_rate = 100 * GIGA
            mac_recfg_pg_rate = 150 * GIGA
        weight = 40
        weight_ucw = 60
        weight_mcw = 50
        weight_inval = 200  # invalid weight value
        acceptable_epsilon = large_cir_rate / 10  # biggest acceptable difference after floating point approximations

        enabled_status = True
        enabled_status_get = False
        rate_get = 0
        weight_get = 0
        weight_mcw_get = 0
        burst_get = 0

        ts = self.device.get_ifg_scheduler(slice_id, ifg_id)
        self.assertNotEqual(ts, None)

        _mac_port = T.mac_port(self, self.device, slice_id, ifg_id, first_serdes_id, last_serdes_id)
        sys_port = T.system_port(self, self.device, sys_port_gid, _mac_port)

        ifc_sch = _mac_port.hld_obj.get_scheduler()
        self.assertIsNotNone(ifc_sch)

        tpts = sys_port.hld_obj.get_scheduler()
        self.assertNotEqual(tpts, None)

        tpts.set_priority_propagation(enabled_status)
        enabled_status_get = tpts.get_priority_propagation()
        self.assertEqual(enabled_status_get, enabled_status)
        enabled_status_get = False  # return to pre-test state

        ifc_sch.set_transmit_cir(large_cir_rate)
        rate_get = ifc_sch.get_transmit_cir()
        self.assertAlmostEqual(rate_get, large_cir_rate, delta=large_cir_rate / 100)
        rate_get = 0  # return to pre-test state

        pir_rate = akpg_pir_rate if decor.is_akpg() else large_pir_rate
        if not decor.is_akpg() or decor.is_asic3():
            ifc_sch.set_transmit_eir_or_pir(pir_rate, enabled_status)
            rate_get, enabled_status_get = ifc_sch.get_transmit_eir_or_pir()
            self.assertAlmostEqual(rate_get, pir_rate, delta=pir_rate / 100)
        else:
            # akpg does not support EIR at the Interface level (except asic3)
            try:
                ifc_sch.set_transmit_eir_or_pir(large_pir_rate, enabled_status)
                self.assertFail()
            except sdk.BaseException:
                pass
            enabled_status = False
            ifc_sch.set_transmit_eir_or_pir(akpg_pir_rate, enabled_status)
            rate_get, enabled_status_get = ifc_sch.get_transmit_eir_or_pir()
            self.assertAlmostEqual(rate_get, akpg_pir_rate, delta=akpg_pir_rate   / 100)
        self.assertEqual(enabled_status_get, enabled_status)
        rate_get = 0  # return to pre-test state
        enabled_status_get = False  # return to pre-test state

        ifc_sch.set_cir_weight(weight)
        weight_get = ifc_sch.get_cir_weight()
        self.assertEqual(weight, weight_get)
        weight_get = 0  # return to pre-test state

        ifc_sch.set_eir_weight(weight)
        weight_get = ifc_sch.get_eir_weight()
        self.assertEqual(weight, weight_get)
        weight_get = 0  # return to pre-test state

        ifc_sch.set_transmit_eir_or_pir(full_pir_rate, enabled_status)  # return pir_rate to default status

        oqcs = tpts.get_output_queue_scheduler(oid)
        self.assertNotEqual(oqcs, None)

        tpts.set_transmit_pir_burst_size(oid, LEGAL_BURST_SIZES[0])
        tpts.set_transmit_pir(oid, large_pir_rate)
        burst_get = tpts.get_transmit_pir_burst_size(oid)
        # If scheduler is set to a larger rate than underlying mac_port speed it
        # will be automatically disabled and burst size will be set to LA_BURST_UNLIMITED = 511
        self.assertEqual(burst_get, LA_BURST_UNLIMITED)
        burst_get = 0  # return to pre-test state
        rate_get = tpts.get_transmit_pir(oid)
        # If scheduler is set to a larger rate than underlying mac_port speed it
        # will be automatically disabled and return LA_RATE_UNLIMITED == -1
        self.assertAlmostEqual(LA_RATE_UNLIMITED, rate_get, delta=acceptable_epsilon)
        rate_get = 0  # return to pre-test state

        tpts.set_transmit_pir(oid, good_pir_rate)
        rate_get = tpts.get_transmit_pir(oid)
        self.assertAlmostEqual(good_pir_rate, rate_get, delta=acceptable_epsilon)
        rate_get = 0  # return to pre-test state
        burst_get = tpts.get_transmit_pir_burst_size(oid)
        self.assertEqual(burst_get, LEGAL_BURST_SIZES[0])
        burst_get = 0  # return to pre-test state

        # For GB, burst size is set to zero for transmit pir zero.
        if self.device.ll_device.is_gibraltar():
            tpts.set_transmit_pir(oid, zero_rate)
            rate_get = tpts.get_transmit_pir(oid)
            self.assertAlmostEqual(zero_rate, rate_get, delta=acceptable_epsilon)
            rate_get = 0  # return to pre-test state
            burst_get = tpts.get_transmit_pir_burst_size(oid)
            self.assertEqual(burst_get, 0)
            burst_get = 0  # return to pre-test state

        tpts.set_oq_priority_group(oid, pg)
        pg_get = tpts.get_oq_priority_group(oid)
        self.assertEqual(pg, pg_get)
        pg_get = None  # return to pre-test state

        try:
            tpts.set_transmit_uc_mc_weight(oid, weight_inval, weight_mcw)
            self.assertFail()
        except sdk.BaseException:
            pass

        try:
            tpts.set_transmit_uc_mc_weight(oid, weight_ucw, weight_inval)
            self.assertFail()
        except sdk.BaseException:
            pass

        tpts.set_transmit_uc_mc_weight(oid, weight_ucw, weight_mcw)
        (weight_get, weight_mcw_get) = tpts.get_transmit_uc_mc_weight(oid)
        self.assertEqual(weight_get, weight_ucw)
        self.assertEqual(weight_mcw_get, weight_mcw)
        weight_get = 0  # return to pre-test state
        weight_mcw_get = 0  # return to pre-test state

        ifc_sch.set_transmit_cir(full_cir_rate)  # return cir_rate to default status
        tpts.set_priority_group_transmit_burst_size(pg, LEGAL_BURST_SIZES[0])
        tpts.set_priority_group_transmit_cir(pg, large_cir_rate)
        burst_get = tpts.get_priority_group_transmit_burst_size(pg)
        # If scheduler is set to a larger rate than underlying mac_port speed it
        # will be automatically disabled and burst size will be set to LA_BURST_UNLIMITED = 511
        self.assertEqual(burst_get, LA_BURST_UNLIMITED)
        burst_get = 0  # return to pre-test state
        rate_get = tpts.get_priority_group_transmit_cir(pg)
        # If scheduler is set to a larger rate than underlying mac_port speed it
        # will be automatically disabled and return LA_RATE_UNLIMITED == -1
        self.assertAlmostEqual(LA_RATE_UNLIMITED, rate_get, delta=acceptable_epsilon)
        rate_get = 0  # return to pre-test state

        tpts.set_priority_group_transmit_cir(pg, good_cir_rate)
        rate_get = tpts.get_priority_group_transmit_cir(pg)
        self.assertAlmostEqual(good_cir_rate, rate_get, delta=acceptable_epsilon)
        rate_get = 0  # return to pre-test state
        burst_get = tpts.get_priority_group_transmit_burst_size(pg)
        self.assertEqual(burst_get, LEGAL_BURST_SIZES[0])
        burst_get = 0  # return to pre-test state

        # For GB, burst size is set to zero for transmit cir zero.
        if self.device.ll_device.is_gibraltar():
            tpts.set_priority_group_transmit_cir(pg, zero_rate)
            rate_get = tpts.get_priority_group_transmit_cir(pg)
            self.assertAlmostEqual(zero_rate, rate_get, delta=acceptable_epsilon)
            rate_get = 0  # return to pre-test state
            burst_get = tpts.get_priority_group_transmit_burst_size(pg)
            self.assertEqual(burst_get, 0)
            burst_get = 0  # return to pre-test state

        tpts.set_priority_group_eir_weight(pg, weight)
        weight_get = tpts.get_priority_group_eir_weight(pg)
        self.assertEqual(weight_get, weight)

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

        # Oq transmit pir
        tpts.set_transmit_pir(oid, mac_recfg_pir_rate)
        rate_get = tpts.get_transmit_pir(oid)
        self.assertAlmostEqual(mac_recfg_pir_rate, rate_get, delta=acceptable_epsilon)
        rate_get = 0  # return to pre-test state

        # Oq transmit burst size
        tpts.set_transmit_pir_burst_size(oid, LEGAL_BURST_SIZES[0])
        burst_get = tpts.get_transmit_pir_burst_size(oid)
        self.assertEqual(LEGAL_BURST_SIZES[0], burst_get)
        burst_get = 0  # return to pre-test state.

        # Pg transmit cir
        tpts.set_priority_group_transmit_cir(pg, mac_recfg_pg_rate)
        rate_get = tpts.get_priority_group_transmit_cir(pg)
        self.assertAlmostEqual(mac_recfg_pg_rate, rate_get, delta=acceptable_epsilon)
        rate_get = 0  # return to pre-test state

        # Pg transmit burst size
        tpts.set_priority_group_transmit_burst_size(pg, LEGAL_BURST_SIZES[0])
        burst_get = tpts.get_priority_group_transmit_burst_size(pg)
        self.assertEqual(LEGAL_BURST_SIZES[0], burst_get)
        burst_get = 0  # return to pre-test state.

        # Reconfigure underlying mac port with 10G speed.
        mac_rcfg_serdes_count = 1
        _mac_port.hld_obj.reconfigure(mac_rcfg_serdes_count,
                                      sdk.la_mac_port.port_speed_e_E_10G,
                                      sdk.la_mac_port.fc_mode_e_NONE,
                                      sdk.la_mac_port.fc_mode_e_NONE,
                                      sdk.la_mac_port.fec_mode_e_KR)

        rate_get = tpts.get_transmit_pir(oid)
        # If scheduler is set to a larger rate than underlying mac_port speed it
        # will be automatically disabled and return LA_RATE_UNLIMITED == -1
        self.assertAlmostEqual(LA_RATE_UNLIMITED, rate_get, delta=acceptable_epsilon)
        rate_get = 0  # return to pre-test state.

        burst_get = tpts.get_transmit_pir_burst_size(oid)
        # If scheduler is set to a larger rate than underlying mac_port speed it
        # will be automatically disabled and return burst size UNLIMITED == 511
        self.assertEqual(LA_BURST_UNLIMITED, burst_get)
        burst_get = 0  # return to pre-test state.

        rate_get = tpts.get_priority_group_transmit_cir(pg)
        # If scheduler is set to a larger rate than underlying mac_port speed it
        # will be automatically disabled and return LA_RATE_UNLIMITED == -1
        self.assertAlmostEqual(LA_RATE_UNLIMITED, rate_get, delta=acceptable_epsilon)
        rate_get = 0  # return to pre-test state.

        burst_get = tpts.get_priority_group_transmit_burst_size(pg)
        # If scheduler is set to a larger rate than underlying mac_port speed it
        # will be automatically disabled and return burst size UNLIMITED == 511
        self.assertEqual(LA_BURST_UNLIMITED, burst_get)
        burst_get = 0  # return to pre-test state.

        # transmit_pir
        try:
            tpts.set_transmit_pir_burst_size(oid, OVERSIZE_BURST_SIZE)
            self.assertFail()
        except sdk.BaseException:
            pass

        for bucket_size in LEGAL_BURST_SIZES:
            tpts.set_transmit_pir_burst_size(oid, bucket_size)
            res_bucket_size = tpts.get_transmit_pir_burst_size(oid)
            self.assertEqual(res_bucket_size, bucket_size)

        # 0 locks the shaper due to bug in the Pacific
        tpts.set_transmit_pir_burst_size(oid, 0)
        res_bucket_size = tpts.get_transmit_pir_burst_size(oid)
        self.assertEqual(res_bucket_size, 0)

        if self.device.ll_device.is_pacific():
            with self.assertRaises(sdk.BaseException):
                tpts.set_transmit_pir_burst_size(oid, LEGAL_BURST_SIZES[0])
        else:
            tpts.set_transmit_pir_burst_size(oid, LEGAL_BURST_SIZES[0])

        # priority_group_transmit
        try:
            tpts.set_priority_group_transmit_burst_size(pg, OVERSIZE_BURST_SIZE)
            self.assertFail()
        except sdk.BaseException:
            pass

        for bucket_size in LEGAL_BURST_SIZES:
            tpts.set_priority_group_transmit_burst_size(pg, bucket_size)
            res_bucket_size = tpts.get_priority_group_transmit_burst_size(pg)
            self.assertEqual(res_bucket_size, bucket_size)

        # 0 locks the shaper due to bug in the Pacific
        tpts.set_priority_group_transmit_burst_size(pg, 0)
        res_bucket_size = tpts.get_priority_group_transmit_burst_size(pg)
        self.assertEqual(res_bucket_size, 0)

        if self.device.ll_device.is_pacific():
            with self.assertRaises(sdk.BaseException):
                tpts.set_priority_group_transmit_burst_size(pg, LEGAL_BURST_SIZES[0])
        else:
            tpts.set_priority_group_transmit_burst_size(pg, LEGAL_BURST_SIZES[0])

    def test_set_get_transmit_uc_mc_weight(self):
        slice_id = T.get_device_slice(2)  # valid slice id
        ifg_id = 0   # valid ifg id
        first_serdes_id = 0
        last_serdes_id = 1
        sys_port_gid = 10

        ts = self.device.get_ifg_scheduler(slice_id, ifg_id)
        self.assertNotEqual(ts, None)

        _mac_port = T.mac_port(self, self.device, slice_id, ifg_id, first_serdes_id, last_serdes_id)
        sys_port = T.system_port(self, self.device, sys_port_gid, _mac_port)
        tpts = sys_port.hld_obj.get_scheduler()
        self.assertNotEqual(tpts, None)

        for oid in range(OQ_COUNT):
            weight_ucw = 10 + oid
            weight_mcw = 20 + oid
            tpts.set_transmit_uc_mc_weight(oid, weight_ucw, weight_mcw)

        for oid in range(OQ_COUNT):
            weight_ucw = 10 + oid
            weight_mcw = 20 + oid
            (weight_ucw_get, weight_mcw_get) = tpts.get_transmit_uc_mc_weight(oid)
            self.assertEqual(weight_ucw_get, weight_ucw)
            self.assertEqual(weight_mcw_get, weight_mcw)


if __name__ == '__main__':
    unittest.main()
