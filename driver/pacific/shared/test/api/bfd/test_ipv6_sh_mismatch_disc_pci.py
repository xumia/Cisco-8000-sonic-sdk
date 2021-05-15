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

import unittest
from leaba import sdk
from packet_test_utils import *
from scapy.all import *
from bfd_ipv6_base import *
from bfd_local_pci import *
import decor
import topology as T
import ip_test_base


@unittest.skipIf(decor.is_hw_device(), "Skip on HW device.")
class bfd_single_hop_mismatch_disc(bfd_local, bfd_ipv6_base):

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_bfd_single_hop_mismatch_disc(self):

        run_and_compare(self,
                        self.device,
                        self.INPUT_IPV6_SH_MISMATCH_DISC_PACKET,
                        T.RX_SLICE,
                        T.RX_IFG,
                        T.FIRST_SERDES,
                        self.PUNT_PACKET_IPV6_SH_MISMATCH_DISC_PACKET,
                        self.PCI_PUNT_SLICE,
                        self.PCI_IFG,
                        self.device.get_pci_serdes())

        packets, bytes = self.bfd_mismatch_counter.read(0, True, True)
        self.assertEqual(packets, 1)


if __name__ == '__main__':
    unittest.main()
