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

from pvv_base import *
import unittest
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class l2_p_busy(pvv_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_l2_p_busy(self):

        ac_port1 = T.l2_ac_port(self, self.device, L2_AC_PORT_GID, self.topology.filter_group_def, None, self.eth_port, None, 0, 0)

        try:
            self.device.create_ac_l2_service_port(L2_AC_PORT_GID + 1,
                                                  self.eth_port.hld_obj,
                                                  0,
                                                  0,
                                                  self.topology.filter_group_def,
                                                  self.topology.ingress_qos_profile_def.hld_obj,
                                                  self.topology.egress_qos_profile_def.hld_obj)
            self.assertFail()
        except sdk.BaseException:
            pass


if __name__ == '__main__':
    unittest.main()
