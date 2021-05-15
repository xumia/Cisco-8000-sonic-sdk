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

import time
import unittest
from leaba import sdk
from leaba import debug
import decor
import lldcli

from shut_no_shut_base import *


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class shut_no_shut_serdes_lb_test(shut_no_shut_base):
    loop_mode = 'serdes'
    p2p_ext = False

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_shut_all_ports(self):
        self._test_shut_all_ports()

    @unittest.skipIf(decor.is_gibraltar(), "Test is not yet enabled on GB")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_shut_all_ports_low_power(self):
        self._test_shut_all_ports_low_power()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_shut_mlp_all_ports_with_traffic(self):
        self._test_shut_mlp_all_ports_with_traffic()


if __name__ == '__main__':
    unittest.main()
