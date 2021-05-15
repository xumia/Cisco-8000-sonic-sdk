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

import unittest
import topology as T
from leaba import sdk
import decor
from mac_port_packet_size_base import *

SA_MIN_SIZE = 64
SA_MAX_SIZE = 10012
SLICE_ID = 2
IFG_ID = 1

if (decor.is_asic4() or decor.is_asic3()):
    FIRST_SERDES = 14
    LAST_SERDES = 15
else:
    FIRST_SERDES = 16
    LAST_SERDES = 17


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class max_port_packet_size_sa(mac_port_packet_size_base):
    def setUp(self):
        import sim_utils
        self.device = sim_utils.create_device(0, slice_modes=sim_utils.STANDALONE_DEV)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    def test_min_max_packet_size_sa(self):
        if T.is_matilda_model(self.device):
            self.skipTest("This device does not support serdes speed >25. Thus, this test is irrelevant.")
            return
        self.mac_port_max_min_size_test(SA_MAX_SIZE, SA_MIN_SIZE, SLICE_ID, IFG_ID, 8, 9)
        self.mac_port_max_min_size_test(SA_MAX_SIZE, SA_MIN_SIZE, SLICE_ID, IFG_ID, FIRST_SERDES, LAST_SERDES)

    def tearDown(self):
        self.device.tearDown()


if __name__ == '__main__':
    unittest.main()
