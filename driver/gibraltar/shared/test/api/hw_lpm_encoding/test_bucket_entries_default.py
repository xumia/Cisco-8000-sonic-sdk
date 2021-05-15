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

from routing_lookup_base import *
import math
from lpm_parameters import lpm_configuration
import ipaddress


class bucket_lookup(lpm_routing):
    def _test_bucket_lookup(self):
        max_entries_in_bucket = lpm_configuration['L2_BUCKET_SIZE']

        # checking all buckets entries
        base_dip = ipaddress.ip_address("10.56.0.0")
        dips = []
        for i in range(max_entries_in_bucket):
            dips.append((base_dip, 32))
            base_dip += 1

        # checking all buckets entries
        dips.append((base_dip, 8))

        self._packets_lookup(dips)


class sram_bucket_lookup(bucket_lookup):
    def test_bucket_lookup(self):
        self._test_bucket_lookup()


@unittest.skipIf(not lpm_routing.RUN_HBM, "Running only on boards with HBM")
class hbm_bucket_lookup(bucket_lookup):

    def test_bucket_lookup(self):
        self._populate_sram()
        self._test_bucket_lookup()

    def _populate_sram(self):
        print("populating SRAM")
        DROP_NH_MAC = 0xaabb
        DROP_NH_GID = 10

        self.device.set_int_property(sdk.la_device_property_e_LPM_REBALANCE_INTERVAL, 1000000)
        ipv4_prefix = sdk.la_ipv4_prefix_t()
        ipv4_prefix.length = 32
        ipv4_prefix.addr.s_addr = int(ipaddress.ip_address('240.0.0.0'))

        mac = sdk.la_mac_addr_t()
        mac.flat = 0xaabb
        drop_nh = self.device.create_next_hop(DROP_NH_GID, mac, None, sdk.la_next_hop.nh_type_e_DROP)

        # filling the SRAM with unused prefixes.
        # Number of prefixes in the SRAM = NUM_SRAM_LINES * how many entries will fit in each line.
        sram_size_one_core = lpm_configuration['NUM_SRAM_LINES'] * \
            (2 ** (math.floor(math.log2(lpm_configuration['L2_BUCKET_SIZE']))))
        prefixes_action_vec = []
        for i in range(sram_size_one_core):
            ipv4_prefix.addr.s_addr += 1
            prefix_action = sdk.la_ipv4_route_entry_parameters()
            prefix_action.action = sdk.la_route_entry_action_e_ADD
            prefix_action.destination = drop_nh
            prefix_action.user_data = PRIVATE_DATA
            prefix_action.prefix = ipv4_prefix
            prefix_action.latency_sensitive = False
            prefixes_action_vec.append(prefix_action)
        self.vrf.ipv4_route_bulk_updates(prefixes_action_vec)


if __name__ == '__main__':
    unittest.main()
