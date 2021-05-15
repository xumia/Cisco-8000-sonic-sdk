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


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class test_persistent_token(unittest.TestCase):

    def setUp(self):
        self.token_in = 127

    def tearDown(self):
        pass

    def persistent_token_value_check_through_phases(self, device, phase):
        if phase == sdk.la_device.init_phase_e_CREATED:
            device.write_persistent_token(self.token_in)

        token_out = device.read_persistent_token()

        self.assertEqual(self.token_in, token_out)

    @unittest.skipUnless(decor.is_hw_device(), "Test is disabled in simulation")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_persistent_token_through_init_phases(self):
        dev_id = 1
        # Passing a function to create_device that will test at each phase if any changes happen to the persistent token
        import sim_utils
        uut_device = sim_utils.create_device(dev_id, device_config_func=self.persistent_token_value_check_through_phases)
        uut_device.tearDown()
        # Now we don't initialize the device fully, because
        # 1) Getting to phase TOPOLOGY would require a powercycle on GB, which would definetly clear the token
        # 2) We should be able to read the token straight from the phase CREATED
        uut_device = sim_utils.create_device(dev_id, initialize=False)
        uut_device.write_persistent_token(self.token_in)
        token_out = uut_device.read_persistent_token()
        self.assertEqual(self.token_in, token_out)
        uut_device.tearDown()


if __name__ == '__main__':
    unittest.main()
