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


import decor
import unittest
from leaba import sdk
import sim_utils
import packet_test_utils as U
import scapy.all as S
import topology as T
import warm_boot_counters_base
import warm_boot_test_utils as wb


wb.support_warm_boot()


@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
@unittest.skipIf(decor.is_auto_warm_boot_enabled(), "Skip in auto-WB sanity")
@unittest.skipUnless(decor.is_pacific() or decor.is_gibraltar(), "WB is currently supported by GB and PAC only")
class warm_boot_voq_counters_test(warm_boot_counters_base.warm_boot_voq_counters_base):

    @unittest.skipIf(decor.is_asic3(), "Warm boot is not supported on GR")
    def test_warm_boot_voq_counters_packet_enqueued(self):
        # create and attach counter
        counter = self.create_and_attach_counter()

        # verify the counter is empty
        wb.warm_boot(self.device.device)
        self.check_counter_values(counter,
                                  exp_enq_pkts=0, exp_enq_bytes=0,
                                  exp_drop_pkts=0, exp_drop_bytes=0)

        U.run_and_compare(
            self,
            self.device,
            self.IN_PACKET_ENQUEUE,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.OUT_PACKET_ENQUEUE,
            T.TX_SLICE_REG,
            T.TX_IFG_REG,
            T.FIRST_SERDES_SVI)

        # verify counter's ENQUEUE/DROP values are as expected
        expected_packet_size = U.get_injected_packet_len(self.device, self.IN_PACKET_ENQUEUE, T.RX_SLICE)
        wb.warm_boot(self.device.device)
        self.check_counter_values(counter,
                                  exp_enq_pkts=1, exp_enq_bytes=expected_packet_size,
                                  exp_drop_pkts=0, exp_drop_bytes=0)

    def test_warm_boot_voq_counters_packet_dropped(self):
        # Save current trap configuration
        wb.warm_boot(self.device.device)
        prev_trap_config = self.device.get_trap_configuration(sdk.LA_EVENT_ETHERNET_NO_SERVICE_MAPPING)

        # Configure trap to superior priority and to drop
        wb.warm_boot(self.device.device)
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_NO_SERVICE_MAPPING, 0, None, None, False, True, True, 0)

        # get drop counter
        wb.warm_boot(self.device.device)
        counter = self.device.get_forwarding_drop_counter()

        # verify the counter is empty
        wb.warm_boot(self.device.device)
        self.check_counter_values(counter,
                                  exp_enq_pkts=0, exp_enq_bytes=0,
                                  exp_drop_pkts=0, exp_drop_bytes=0)

        U.run_and_drop(
            self,
            self.device,
            self.IN_PACKET_DROP,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES)

        expected_packet_size = U.get_injected_packet_len(self.device, self.IN_PACKET_DROP, T.RX_SLICE)
        wb.warm_boot(self.device.device)
        self.check_counter_values(counter,
                                  exp_enq_pkts=0, exp_enq_bytes=0,
                                  exp_drop_pkts=1, exp_drop_bytes=expected_packet_size)

    def test_warm_boot_voq_counters_packet_enqueued_sdk_down_kernel_module_up(self):
        # create and attach counter
        counter = self.create_and_attach_counter()

        # verify the counter is empty
        self.check_counter_values(counter,
                                  exp_enq_pkts=0, exp_enq_bytes=0,
                                  exp_drop_pkts=0, exp_drop_bytes=0)

        py_objs_metadata = wb.warm_boot_disconnect(self.device.device, self.warm_boot_file_name)

        U.run_and_compare(
            self,
            self.device,
            self.IN_PACKET_ENQUEUE,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES,
            self.OUT_PACKET_ENQUEUE,
            T.TX_SLICE_REG,
            T.TX_IFG_REG,
            T.FIRST_SERDES_SVI)

        wb.warm_boot_reconnect(py_objs_metadata, self.warm_boot_file_name)

        # verify counter's ENQUEUE/DROP values are as expected
        expected_packet_size = U.get_injected_packet_len(self.device, self.IN_PACKET_ENQUEUE, T.RX_SLICE)
        self.check_counter_values(counter,
                                  exp_enq_pkts=1, exp_enq_bytes=expected_packet_size,
                                  exp_drop_pkts=0, exp_drop_bytes=0)

    def test_warm_boot_voq_counters_packet_dropped_sdk_down_kernel_module_up(self):
        # Save current trap configuration
        prev_trap_config = self.device.get_trap_configuration(sdk.LA_EVENT_ETHERNET_NO_SERVICE_MAPPING)

        # Configure trap to superior priority and to drop
        self.device.set_trap_configuration(sdk.LA_EVENT_ETHERNET_NO_SERVICE_MAPPING, 0, None, None, False, True, True, 0)

        # get drop counter
        counter = self.device.get_forwarding_drop_counter()

        # verify the counter is empty
        self.check_counter_values(counter,
                                  exp_enq_pkts=0, exp_enq_bytes=0,
                                  exp_drop_pkts=0, exp_drop_bytes=0)

        py_objs_metadata = wb.warm_boot_disconnect(self.device.device, self.warm_boot_file_name)

        U.run_and_drop(
            self,
            self.device,
            self.IN_PACKET_DROP,
            T.RX_SLICE,
            T.RX_IFG,
            T.FIRST_SERDES)

        wb.warm_boot_reconnect(py_objs_metadata, self.warm_boot_file_name)

        expected_packet_size = U.get_injected_packet_len(self.device, self.IN_PACKET_DROP, T.RX_SLICE)
        self.check_counter_values(counter,
                                  exp_enq_pkts=0, exp_enq_bytes=0,
                                  exp_drop_pkts=1, exp_drop_bytes=expected_packet_size)


if __name__ == '__main__':
    unittest.main()
