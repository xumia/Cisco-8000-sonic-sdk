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

from packet_test_utils import *
from scapy.all import *
import unittest
from leaba import sdk
import sim_utils
import topology as T


class vlan_vlan_with_fallback_base(unittest.TestCase):
    RX_AC_PORT_GID = 0xabc
    RX_FALLBACK_AC_PORT_GID = 0xdef
    RX_AC_PORT_VID1 = 0x987
    RX_AC_PORT_VID2 = 0x654
    DUMMY_VID2 = 0x321
    DST_MAC = "ca:fe:ca:fe:ca:fe"
    SRC_MAC = "de:ad:de:ad:de:ad"

    RX_SYS_PORT_GID = 0x13
    RX_SERDES_FIRST = T.get_device_first_serdes(2)
    RX_SERDES_LAST = T.get_device_first_serdes(3)

    def setUp(self):
        self.device = sim_utils.create_device(1)

        self.topology = T.topology(self, self.device)

        self.rx_eth_port = T.ethernet_port(
            self,
            self.device,
            T.RX_SLICE,
            T.RX_IFG,
            self.RX_SYS_PORT_GID,
            self.RX_SERDES_FIRST,
            self.RX_SERDES_LAST)
        self.ac_profile = T.ac_profile(self, self.device, with_fallback=True)
        self.rx_eth_port.set_ac_profile(self.ac_profile)

    def tearDown(self):
        self.device.tearDown()
