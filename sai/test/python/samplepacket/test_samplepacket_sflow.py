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

# This test suite is not intended to run by default.
# In order to run these tests, make sure the following conditions are met:
# 1. psample kernel module is loaded on the system you are running
# 2. the test is run with 'sudo' or root access
#
# If the previous conditions are met you can remove the 'skipif' fixture and run the test

from samplepacket_tests import *
import asyncio
import threading
from queue import *
import os


class samplepacket_sflow_tests():
    def __init__(self, ip_version):
        self.samplepacket_test = samplepacket_tests(ip_version)

    def recv_sample_wrapper(self, q):
        ret = swig_wrap_recieve("psample", "packets", 1, 60)
        q.put(ret)
        return

    def _test_samplepacket_sflow(self):
        port_hostif = pytest.tb.create_hostif(
            SAI_HOSTIF_TYPE_NETDEV, pytest.tb.ports[pytest.top.in_port], "TestPort", verify=[True, False])
        hostif_oid = pytest.tb.create_hostif(
            SAI_HOSTIF_TYPE_GENETLINK, None, "psample", "packets", verify=[True, False])
        sample_packet_trap = pytest.tb.create_trap(SAI_HOSTIF_TRAP_TYPE_SAMPLEPACKET, SAI_PACKET_ACTION_TRAP, 255)
        hostif_entry_oid = pytest.tb.create_hostif_table_entry(SAI_HOSTIF_TABLE_ENTRY_TYPE_TRAP_ID,
                                                               None,
                                                               sample_packet_trap,
                                                               SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_GENETLINK,
                                                               hostif_oid,
                                                               verify=[True,
                                                                       False])
        pytest.tb.do_warm_boot()

        queue = Queue()
        thread = threading.Thread(target=self.recv_sample_wrapper, args=[queue])
        thread.start()
        self.samplepacket_test._test_send_packet(pytest.top.in_port, pytest.top.in_port, pytest.top.out_port, True)
        thread.join()
        response = queue.get()
        assert(response is not ())

        pytest.tb.remove_object(hostif_entry_oid)
        pytest.tb.remove_object(sample_packet_trap)
        pytest.tb.remove_object(hostif_oid)


@pytest.mark.usefixtures("basic_route_v4_topology")
class Test_samplepacket_sflow_v4():
    os.system("modprobe psample")
    tests = samplepacket_sflow_tests("v4")

    def test_samplepacket_sflow(self):
        st_utils.skipIf(not pytest.tb.is_hw())
        self.tests._test_samplepacket_sflow()


@pytest.mark.usefixtures("basic_route_v6_topology")
class Test_samplepacket_sflow_v6():
    tests = samplepacket_sflow_tests("v6")

    def test_samplepacket_sflow(self):
        st_utils.skipIf(not pytest.tb.is_hw())
        self.tests._test_samplepacket_sflow()
