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

import xml_rpc_server  # SRM XML-RPC server
import xmlrpc.client
import time
import unittest
import os


class testcase(unittest.TestCase):
    def setUp(self):
        os.environ['ASIC'] = 'GIBRALTAR_A0'

        # Start XML-RPC server and connect a client to it
        # ll_device will be created/owned/destroyed internally by XML-RPC server
        device_id = 17
        devpath = '/dev/testdev'
        server_thread, ip, port = xml_rpc_server.start_thread_standalone('0.0.0.0', 0, device_id, devpath)
        self.server_thread = server_thread
        time.sleep(1)

        uri = 'http://{}:{}'.format(ip, port)
        print('xmlrpc.client: connect to', uri)
        self.server_proxy = xmlrpc.client.ServerProxy(uri)

    def tearDown(self):
        # Issue stop request
        self.server_proxy.control.stop()
        # Wait for server thread
        self.server_thread.join()

    def test_standalone(self):
        # Issue platform_device_* requests
        device_count = self.server_proxy.dev.platform_device_count()
        self.assertEqual(device_count, 128)

        device_index = "0x19"
        # serdes_package 0x19 should be mapped to slice 1, ifg 0, serdes_package 2
        die_id = self.server_proxy.dev.platform_device_die_id(device_index)
        self.assertEqual(die_id, "0x112100")

        # Issue read/writes
        self.server_proxy.dev.reg_set(device_index, "0", "42")
        self.server_proxy.dev.reg_set_list(device_index, "0x00,0x10,0x20", "0xaaaa,0xbbbb,0xcccc")
        val = self.server_proxy.dev.reg_get(device_index, "0")
        vals = self.server_proxy.dev.reg_get_list(device_index, "0x00,0x10,0x20")


if __name__ == '__main__':
    unittest.main()
