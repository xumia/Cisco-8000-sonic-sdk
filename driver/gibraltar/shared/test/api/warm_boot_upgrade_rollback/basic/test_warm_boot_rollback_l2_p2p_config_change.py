#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2021-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import warm_boot_upgrade_rollback_test_utils as wb
from warm_boot_upgrade_rollback_l2_p2p_base import warm_boot_upgrade_rollback_l2_p2p_base


wb.set_up_wb_rollback()


@unittest.skipUnless(decor.is_wb_upgrade_rollback_enabled(), 'This test should run only in WB upgrade/rollback sanity')
@unittest.skipUnless(decor.is_gibraltar(), 'WB upgrade/rollback is supported only on GB')
class warm_boot_upgrade_l2_p2p(warm_boot_upgrade_rollback_l2_p2p_base):

    def test_warm_boot_upgrade_l2_p2p(self):
        self._test_warm_boot_l2_p2p(change_config_after_wb=True)


if __name__ == '__main__':
    unittest.main()
