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


import socket
import time
from scapy.config import conf
conf.ipv6_enabled = False
from scapy.all import *

from packet_test_defs import *
import decor
from sdk_test_case_base import *
import topology as T


HOST_SLICE = 2
HOST_IFG = 0

L2AC_MAC_ADDR = T.mac_addr('10:11:12:13:14:15')


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipUnless(decor.is_hw_device(), "Run only on HW")
class inject_without_header(sdk_test_case_base):

    def setUp(self):

        super().setUp(create_default_topology=False)

        # ports
        rcy_sys_port = T.recycle_sys_port(self, self.device, HOST_SLICE + 1, HOST_IFG, 100)
        pci_port = T.pci_port(self, self.device, HOST_SLICE, HOST_IFG)
        pci_sys_port = T.system_port(self, self.device, 101, pci_port)
        eth_port = T.sa_ethernet_port(self, self.device, pci_sys_port)
        l2ac = T.l2_ac_port(self, self.device, 100, filter_group=None, switch=None, eth_port=eth_port, mac_addr=L2AC_MAC_ADDR)
        l2ac.hld_obj.set_destination(l2ac.hld_obj)
        pci_port.hld_obj.activate()

        # socket
        self.device.open_sockets()

    def __get_packet(self):
        self.device.sockets[HOST_SLICE].settimeout(0.01)
        try:
            output_packet = self.device.sockets[HOST_SLICE].recv(10000)
        except socket.timeout:
            output_packet = None
        return output_packet

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_inject(self):
        # define packet
        INPUT_PACKET = \
            Ether(dst=L2AC_MAC_ADDR.addr_str, src='00:10:94:00:00:02', type=Ethertype.IPv4.value) / \
            IP() / TCP() / Raw(load=bytes(64 * [0]))
        input_packet = bytes(INPUT_PACKET)

        # send packet
        self.device.sockets[HOST_SLICE].send(input_packet)
        time.sleep(1)

        # receive packet
        output_packet = self.__get_packet()
        while output_packet is not None:
            # ignore the wrapper headers from the output packet
            if output_packet[16:] == input_packet:
                return  # success
            output_packet = self.__get_packet()

        # no matching packet was received
        self.assertTrue(False)


if __name__ == '__main__':
    unittest.main()
