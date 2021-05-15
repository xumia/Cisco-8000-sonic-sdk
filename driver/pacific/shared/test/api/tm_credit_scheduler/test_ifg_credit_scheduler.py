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


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class ifg_credit_scheduler(tm_credit_scheduler_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_ifg_credit_scheduler(self):
        slice_id = T.get_device_slice(2)
        ifg_id = 0
        slice_id_inval = 7
        ifg_id_inval = 2

        invalid_rate = int(0.1 * GIGA)
        rate = 10 * GIGA  # 10 Gbps
        rate_get = 0

        burst = 16  # 16 - Max accumulated number of credits in the generator
        burst_get = 0

        slow_rate = 5 * GIGA  # 5 Gbps
        slow_rate_get = 0

        txpdr_rate = 10 * GIGA  # 10 Gbps
        txpdr_rate_get = 0

        txpdr_eir_or_pir_rate = 10 * GIGA
        txpdr_eir_or_pir_rate_get = 0
        if decor.is_akpg():
            is_eir = False
        else:
            is_eir = True

        is_eir_get = False

        txpdr_weight = 5  # non default value
        txpdr_weight_get = 0

        txpdr_eir_weight = 5  # non default value
        txpdr_eir_weight_get = 0

        try:
            self.device.get_ifg_scheduler(slice_id_inval, ifg_id)
            self.fail()
        except sdk.BaseException:
            pass

        try:
            self.device.get_ifg_scheduler(slice_id, ifg_id_inval)
            self.fail()
        except sdk.BaseException:
            pass

        cs = self.device.get_ifg_scheduler(slice_id, ifg_id)
        self.assertNotEqual(cs, None)

        acceptable_epsilon = txpdr_eir_or_pir_rate / 10000
        cs.set_txpdr_eir_or_pir(txpdr_eir_or_pir_rate, is_eir)
        txpdr_eir_or_pir_rate_get, is_eir_get = cs.get_txpdr_eir_or_pir()
        self.assertAlmostEqual(txpdr_eir_or_pir_rate, txpdr_eir_or_pir_rate_get, delta=acceptable_epsilon)
        self.assertEqual(is_eir_get, is_eir)

        acceptable_epsilon = txpdr_rate / 10000
        cs.set_txpdr_cir(txpdr_rate)
        txpdr_rate_get = cs.get_txpdr_cir()
        self.assertAlmostEqual(txpdr_rate_get, txpdr_rate, delta=acceptable_epsilon)

        cs.set_txpdr_cir_weight(txpdr_weight)
        txpdr_weight_get = cs.get_txpdr_cir_weight()
        self.assertEqual(txpdr_weight_get, txpdr_weight)

        cs.set_txpdr_eir_weight(txpdr_eir_weight)
        txpdr_eir_weight_get = cs.get_txpdr_eir_weight()
        self.assertEqual(txpdr_eir_weight, txpdr_eir_weight_get)


if __name__ == '__main__':
    unittest.main()
