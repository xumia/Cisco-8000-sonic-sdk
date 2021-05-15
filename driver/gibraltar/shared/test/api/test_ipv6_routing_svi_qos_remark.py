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

import sys
import unittest
from leaba import sdk
import ip_test_base
import packet_test_utils as U
import scapy.all as S
import sim_utils
import topology as T
import ip_routing_qos_remark_base
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class ipv6_rx_svi_untagged_ip_routing_qos_remark_test(
        ip_routing_qos_remark_base.ip_routing_qos_remark_test,
        ip_routing_qos_remark_base.ipv6_test,
        ip_routing_qos_remark_base.rx_svi_test,
        ip_routing_qos_remark_base.egress_untagged_test):
    pass


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class ipv6_rx_svi_tagged_ip_routing_qos_remark_test(
        ip_routing_qos_remark_base.ip_routing_qos_remark_test,
        ip_routing_qos_remark_base.ipv6_test,
        ip_routing_qos_remark_base.rx_svi_test,
        ip_routing_qos_remark_base.egress_tagged_test):
    pass


if __name__ == '__main__':
    unittest.main()
