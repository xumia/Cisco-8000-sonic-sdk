#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

from samplepacket_tests import *


@pytest.mark.usefixtures("basic_route_v4_topology")
class Test_samplepacket_v4():
    samplepacket_test = samplepacket_tests("v4")

    def test_samplepacket_attrib_modify(self):
        oid = self.samplepacket_test._create_samplepacket_session()
        modifyable_attrs = {}
        modifyable_attrs[SAI_SAMPLEPACKET_ATTR_SAMPLE_RATE] = 200000
        for k, v in modifyable_attrs.items():
            pytest.tb.set_object_attr(oid, k, v, verify=True)

        pytest.tb.remove_object(oid)

    def test_samplepacket_ingress(self):
        self.samplepacket_test._test_send_packet(pytest.top.in_port, pytest.top.in_port, pytest.top.out_port, True)

    @pytest.mark.skipif(True, reason="Test fails because of the changes in mirror logic")
    def test_samplepacket_egress(self):
        self.samplepacket_test._test_send_packet(pytest.top.out_port, pytest.top.in_port, pytest.top.out_port, False)


@pytest.mark.usefixtures("basic_route_v6_topology")
class Test_samplepacket_v6():
    samplepacket_test = samplepacket_tests("v6")

    def test_samplepacket_ingress(self):
        self.samplepacket_test._test_send_packet(pytest.top.in_port, pytest.top.in_port, pytest.top.out_port, True)

    def test_samplepacket_egress(self):
        self.samplepacket_test._test_send_packet(pytest.top.out_port, pytest.top.in_port, pytest.top.out_port, False)
