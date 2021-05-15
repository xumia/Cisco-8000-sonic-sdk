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
import sim_utils
import topology as T
from l3_ac_base import *


class test_set_mac(l3_ac_base):

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_many_ports(self):

        base_mac_addr_str = '33:44:33:44:33'
        ports = []
        N = 3  # There are 11 SA prefixes available, topology uses 8 of them.

        # Create many ports
        for i in range(N):
            mac_addr_prefix = i + 20
            mac_addr_str = '%x:%s' % (mac_addr_prefix, base_mac_addr_str)
            mac_addr = T.mac_addr(mac_addr_str)

            port = T.l3_ac_port(
                self,
                self.device,
                L3_AC_PORT_GID + i,
                self.topology.rx_eth_port,
                self.topology.vrf,
                mac_addr,
                111 + i,
                112 + i)

            ports.append(port)

        # Change the MAC address of the first port
        mac_addr_prefix = N + 1 + 20
        mac_addr_str = '%s:%s' % (mac_addr_prefix, base_mac_addr_str)
        mac_addr = T.mac_addr(mac_addr_str)
        ports[0].hld_obj.set_mac(mac_addr.hld_obj)

        # Cleanup
        for i in range(N):
            ports[i].destroy()


if __name__ == '__main__':
    unittest.main()
