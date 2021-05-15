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
import os

if decor.is_gibraltar() or decor.is_asic4() or decor.is_asic5():
    FEATURE_APB = True
else:
    FEATURE_APB = False

if decor.is_gibraltar():
    FEATURE_SRM = True
else:
    FEATURE_SRM = False

import cpu2jtagcli
if FEATURE_APB:
    import apbcli
if FEATURE_SRM:
    import srmcli

APB_INTERFACE_TYPES = [
    sdk.apb_interface_type_e_PCIE,
    sdk.apb_interface_type_e_SERDES,
    sdk.apb_interface_type_e_HBM,
]


@unittest.skipIf(decor.is_auto_warm_boot_enabled(), "Cannot do WB if device is uninitialized.")
class test_low_level_interfaces(unittest.TestCase):
    '''
        Test availability of low level interfaces: cpu2jtag, apb, hbm-ieee1500
    '''

    def setUp(self):
        self.dev_id = 1
        self.ll_device = None
        self.cpu2jtag_handler = None
        self.device = None
        self.apb_handlers = [None] * len(APB_INTERFACE_TYPES)

    def tearDown(self):
        apb_serdes = self.apb_handlers[sdk.apb_interface_type_e_SERDES]
        if FEATURE_SRM and apb_serdes:
            srmcli.srm_clear_apb(apb_serdes)

        # release all objects owned by Python by assigning 'None'
        for i in range(len(self.apb_handlers)):
            self.apb_handlers[i] = None
        self.cpu2jtag_handler = None
        self.ll_device = None
        if self.device:
            self.device.tearDown()
        self.device = None

    def init(self, use_la_device):
        if use_la_device:
            # create la_device
            import sim_utils
            self.device = sim_utils.create_device(self.dev_id, initialize=True)
            # self.device.initialize_slice_id_manager()
            # Get handlers, the return values are not owned by Python, they are released in C++.
            self.cpu2jtag_handler = self.device.get_cpu2jtag_handler()
            for i in range(len(APB_INTERFACE_TYPES)):
                try:
                    self.apb_handlers[i] = self.device.get_apb_handler(APB_INTERFACE_TYPES[i])
                except BaseException as status:
                    self.assertEqual(status.args[0], sdk.la_status_e_E_NOTIMPLEMENTED)
        else:
            # create 'll_device'
            dev_path = os.getenv('SDK_DEVICE_NAME')
            dev_path = dev_path if dev_path else '/dev/testdev'
            import lldcli
            self.ll_device = lldcli.ll_device_create(self.dev_id, dev_path)

            # objcli.obj_create() returns an object owned by Python. Release in self.tearDown().

            self.cpu2jtag_handler = cpu2jtagcli.cpu2jtag_create(self.ll_device)
            if FEATURE_APB:
                for i in range(len(APB_INTERFACE_TYPES)):
                    self.apb_handlers[i] = apbcli.apb_create(self.ll_device, i)

            if FEATURE_SRM:
                srmcli.srm_set_apb(self.apb_handlers[sdk.apb_interface_type_e_SERDES])

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_get_handlers_from_la_device(self):
        self.init(True)

        self.verify_cpu2jtag(self.cpu2jtag_handler)
        self.verify_apb(self.apb_handlers)
        self.verify_srm(self.device.ll_device)

    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_create_handlers_with_ll_device(self):
        self.init(False)

        self.verify_cpu2jtag(self.cpu2jtag_handler)
        self.verify_apb(self.apb_handlers)
        self.verify_srm(self.ll_device)

    def verify_cpu2jtag(self, cpu2jtag_handler):
        self.assertIsNotNone(cpu2jtag_handler)
        # Check that cpu2jtag Py package functions are callable
        cpu2jtag_handler.enable(1200 * 1000, 5)
        cpu2jtag_handler.disable()

    def verify_apb(self, apb_handlers):
        if FEATURE_APB:
            # All handlers should be not None
            self.assertTrue(all(apb_handlers))

            # Check that apb Py package functions are callable
            for i in range(len(apb_handlers)):
                self.assertEqual(i, apb_handlers[i].get_interface_type())
        else:
            # All handlers should be None
            self.assertFalse(any(apb_handlers))

    def verify_srm(self, ll_device):
        if FEATURE_SRM:
            die = srmcli.get_serdes_addr(srmcli.srm_serdes_addressing_mode_e_SERDES, self.dev_id, 0, 0, 0, 0)
            apb_serdes = srmcli.srm_get_apb(self.dev_id)
            self.assertIsNotNone(apb_serdes)

            # Check that srm Py package functions are callable and APB interface is set.
            rc = srmcli.srm_reg_set(die, 0, 0)
            self.assertEqual(rc, srmcli.IP_OK)
        else:
            pass


if __name__ == '__main__':
    unittest.main()
