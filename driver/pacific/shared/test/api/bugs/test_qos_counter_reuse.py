#!/usr/bin/env python3
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

import decor
import sys
import unittest
from leaba import sdk
from scapy.all import *
import decor
import topology as T
import packet_test_utils as U
from sdk_test_case_base import *
import smart_slices_choise as ssch
import tempfile
import json


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class qos_counter_reuse_tester(sdk_test_case_base):

    def setUp(self):
        super().setUp()

    def get_qos_counter_usage(self, port_slice, port_ifg):
        tmp_fd = tempfile.NamedTemporaryFile(suffix=".json")

        options = sdk.save_state_options()
        options.internal_states.append('counters')

        self.device.device.save_state(options, tmp_fd.name)
        with open(tmp_fd.name) as fp:
            resources = json.load(fp)

        banks = resources['internals'][0]['counter_banks']

        offset = port_ifg + ((port_slice % 2) * 2)
        for bank in banks:
            if ('METER' in bank['allowed_users']):
                if (port_slice in range(bank['first_slice'], bank['first_slice'] + bank['num_slices'])):
                    allocations = bank['physical_banks'][offset]['allocations']
                    for entry in allocations:
                        if ('QOS' in entry['user']):
                            return entry['used']

        return 0

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
    def test_counter_reuse(self):
        counter = self.device.create_counter(2)

        self.assertEqual(self.get_qos_counter_usage(T.RX_SLICE, T.RX_IFG), 0)
        # Attach counter to 2 interfaces
        self.topology.rx_l3_ac.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_QOS, counter)
        self.topology.rx_l3_ac1.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_QOS, counter)

        # Meters use 3 counters per object. 2 meters will use 6 physical counters
        self.assertEqual(self.get_qos_counter_usage(T.RX_SLICE, T.RX_IFG), 6)

        self.topology.tx_l3_ac_ext.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_QOS, counter)
        self.assertEqual(self.get_qos_counter_usage(T.TX_SLICE_EXT, T.TX_IFG_EXT), 6)

        # Release counter from 2 interfaces
        self.topology.tx_l3_ac_ext.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_QOS, None)
        self.topology.rx_l3_ac.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_QOS, None)
        self.topology.rx_l3_ac1.hld_obj.set_ingress_counter(sdk.la_counter_set.type_e_QOS, None)

        self.assertEqual(self.get_qos_counter_usage(T.RX_SLICE, T.RX_IFG), 0)
        self.assertEqual(self.get_qos_counter_usage(T.TX_SLICE_EXT, T.TX_IFG_EXT), 0)
        # Destroy counter
        self.device.destroy(counter)


if __name__ == '__main__':
    unittest.main()
