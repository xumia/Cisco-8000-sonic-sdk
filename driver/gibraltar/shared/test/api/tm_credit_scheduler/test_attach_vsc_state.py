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

global FIRST_SERDES_ID, LAST_SERDES_ID, SLICE_ID
SLICE_ID = T.get_device_slice(3)
IFG_ID = 0

if decor.is_akpg():
    FIRST_SERDES_ID = 14
    LAST_SERDES_ID = 15
    CIR_RR = [sdk.la_oq_vsc_mapping_e_RR0]
    EIR_RR = [sdk.la_oq_vsc_mapping_e_RR2]
    P8_RR = [sdk.la_oq_vsc_mapping_e_RR4]
else:
    FIRST_SERDES_ID = 16
    LAST_SERDES_ID = FIRST_SERDES_ID + 1
    CIR_RR = [sdk.la_oq_vsc_mapping_e_RR0, sdk.la_oq_vsc_mapping_e_RR1]
    EIR_RR = [sdk.la_oq_vsc_mapping_e_RR2, sdk.la_oq_vsc_mapping_e_RR3]
    P8_RR = [sdk.la_oq_vsc_mapping_e_RR4]
SYS_PORT_GID = 0x300

if decor.is_asic5():
    INGRESS_DEVICE = 1  # Asic5 does not support remote device for now
else:
    INGRESS_DEVICE = 5
INGRESS_SLICE = T.get_device_slice(4)
VSC = 500
INGRESS_VOQ_ID = 600


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class logical_port_credit_scheduler(tm_credit_scheduler_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_logical_port_credit_scheduler(self):
        global SLICE_ID, FIRST_SERDES_ID, LAST_SERDES_ID
        SLICE_ID = T.choose_active_slices(self.device, SLICE_ID, [1, 3, 5])
        if self.device.get_int_property(sdk.la_device_property_e_MATILDA_MODEL_TYPE) in [4, 5]:
            FIRST_SERDES_ID = 14
            LAST_SERDES_ID = FIRST_SERDES_ID + 1
        mac_port = T.mac_port(self, self.device, SLICE_ID, IFG_ID, FIRST_SERDES_ID, LAST_SERDES_ID)
        sys_port = T.system_port(self, self.device, SYS_PORT_GID, mac_port)

        tpse = sys_port.hld_obj.get_scheduler()
        self.assertNotEqual(tpse, None)

        # Check attachment when logical port disabled. All attachments are legal.
        oqse0 = tpse.get_output_queue_scheduler(0)

        for mapping in (CIR_RR + EIR_RR):
            oqse0.attach_vsc(INGRESS_VOQ_ID, mapping, INGRESS_DEVICE, T.get_device_slice(1), INGRESS_VOQ_ID)

        with self.assertRaises(sdk.InvalException):
            oqse0.attach_vsc(INGRESS_VOQ_ID, P8_RR[0], INGRESS_DEVICE, T.get_device_slice(1), INGRESS_VOQ_ID)

        if not decor.is_akpg():
            # AKPG Scheduler Does not support LPSE_2P mode
            tpse.set_logical_port_enabled(True)

            # In logical port mode OQSE0 and OQSE1 are in LPSE_2P mode.

            # OQSE1 must use CIR path in Pacific.
            oqse1 = tpse.get_output_queue_scheduler(1)
            for mapping in CIR_RR:
                oqse1.attach_vsc(INGRESS_VOQ_ID + 1, mapping, INGRESS_DEVICE, 1, INGRESS_VOQ_ID)

            for mapping in (EIR_RR):
                if decor.is_pacific():
                    with self.assertRaises(sdk.InvalException):
                        oqse1.attach_vsc(INGRESS_VOQ_ID + 1, mapping, INGRESS_DEVICE, 1, INGRESS_VOQ_ID)
                else:
                    oqse1.attach_vsc(INGRESS_VOQ_ID + 1, mapping, INGRESS_DEVICE, 1, INGRESS_VOQ_ID)

            # Invalid Mapping
            with self.assertRaises(sdk.InvalException):
                oqse1.attach_vsc(INGRESS_VOQ_ID + 1, P8_RR[0], INGRESS_DEVICE, 1, INGRESS_VOQ_ID)

            # OQSE0 must use EIR path in Pacific.
            for mapping in EIR_RR:
                oqse0.attach_vsc(INGRESS_VOQ_ID, mapping, INGRESS_DEVICE, 1, INGRESS_VOQ_ID)

            for mapping in (CIR_RR):
                if decor.is_pacific():
                    with self.assertRaises(sdk.InvalException):
                        oqse0.attach_vsc(INGRESS_VOQ_ID + 1, mapping, INGRESS_DEVICE, 1, INGRESS_VOQ_ID)
                else:
                    oqse1.attach_vsc(INGRESS_VOQ_ID + 1, mapping, INGRESS_DEVICE, 1, INGRESS_VOQ_ID)

            # Invalid Mapping
            with self.assertRaises(sdk.InvalException):
                oqse0.attach_vsc(INGRESS_VOQ_ID + 1, P8_RR[0], INGRESS_DEVICE, 1, INGRESS_VOQ_ID)

            # All user-generated OQSEs must use EIR path in Pacific.
            lp_queuing_oqse = self.device.create_output_queue_scheduler(
                2, 1, sdk.la_output_queue_scheduler.scheduling_mode_e_LP_SP_SP)
            for mapping in EIR_RR:
                lp_queuing_oqse.attach_vsc(INGRESS_VOQ_ID + 2, mapping, INGRESS_DEVICE, 1, INGRESS_VOQ_ID)

            for mapping in (CIR_RR):
                if decor.is_pacific():
                    with self.assertRaises(sdk.InvalException):
                        lp_queuing_oqse.attach_vsc(INGRESS_VOQ_ID + 2, mapping, INGRESS_DEVICE, 1, INGRESS_VOQ_ID)
                else:
                    lp_queuing_oqse.attach_vsc(INGRESS_VOQ_ID + 2, mapping, INGRESS_DEVICE, 1, INGRESS_VOQ_ID)

            # Invalid Mapping
            with self.assertRaises(sdk.InvalException):
                lp_queuing_oqse.attach_vsc(INGRESS_VOQ_ID + 2, P8_RR[0], INGRESS_DEVICE, 1, INGRESS_VOQ_ID)

            # Check LPSE_4P for LP-queuing
            lp_queuing_oqse.set_scheduling_mode(sdk.la_output_queue_scheduler.scheduling_mode_e_LP_4SP)

            for mapping in (CIR_RR + EIR_RR):
                lp_queuing_oqse.attach_vsc(INGRESS_VOQ_ID + 2, mapping, INGRESS_DEVICE, 1, INGRESS_VOQ_ID)

            with self.assertRaises(sdk.InvalException):
                lp_queuing_oqse.attach_vsc(INGRESS_VOQ_ID + 2, P8_RR[0], INGRESS_DEVICE, 1, INGRESS_VOQ_ID)


if __name__ == '__main__':
    unittest.main()
