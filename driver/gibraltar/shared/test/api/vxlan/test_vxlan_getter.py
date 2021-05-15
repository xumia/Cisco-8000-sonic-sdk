#!/usr/bin/env python3
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

import decor
from leaba import sdk
import packet_test_utils as U
import scapy.all as S
import topology as T
import ip_test_base
import decor
from vxlan_base import *


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class vxlan_l2_getter(vxlan_l2_single_port):
    underlay_ip_impl = ip_test_base.ipv4_test_base
    OVL_DIP = '21.1.1.1'
    OVL_DIP_ROUTE = T.ipv4_addr(OVL_DIP)

    OVL_DIP_1 = '31.1.1.1'
    OVL_DIP_ROUTE_1 = T.ipv4_addr(OVL_DIP_1)

    OVL_SIP = '10.1.1.1'
    OVL_SIP_ROUTE = T.ipv4_addr(OVL_SIP)

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_vxlan_getter(self):
        self.create_recycle_ac_port()
        self.single_port_setup()
        self.l3vxlan_setup()
        self._test_vxlan_get_api()
        self.l3vxlan_destroy()
        self.single_port_destroy()
        self.destroy_recycle_ac_port()


if __name__ == '__main__':
    unittest.main()
