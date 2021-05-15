#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

import topology as T
import dscp_qos_remark_dot1q_base
import unittest
import decor


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class l2_dot1q_packet_dscp_remark_ipv4_test(
        dscp_qos_remark_dot1q_base.dscp_qos_remarking_dot1q_packet_test,
        dscp_qos_remark_dot1q_base.ipv4_test):
    pass


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class l2_dot1q_packet_dscp_remark_ipv6_test(
        dscp_qos_remark_dot1q_base.dscp_qos_remarking_dot1q_packet_test,
        dscp_qos_remark_dot1q_base.ipv6_test):
    pass


if __name__ == '__main__':
    unittest.main()
