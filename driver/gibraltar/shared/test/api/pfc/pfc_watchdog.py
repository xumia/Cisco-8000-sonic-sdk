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

import unittest
from leaba import sdk
import sim_utils
import interrupt_utils
from packet_test_utils import *
from scapy.all import *
from pfc_base import TC_VALUE


class pfc_watchdog():
    def watchdog_test(self, mac_port):
        # Open file descriptors for monitoring PFC notifications
        fd_critical, fd_resource = self.device.open_notification_fds(1 << sdk.la_notification_type_e_PFC_WATCHDOG)

        # Configure watchdog polling for 1s
        mac_port.set_pfc_watchdog_polling_interval(1_000)
        polling_time = mac_port.get_pfc_watchdog_polling_interval()
        self.assertEqual(polling_time, 1_000)

        # verify each queue has polling for 1s
        for x in range(8):
            polling_time = mac_port.get_pfc_queue_watchdog_polling_interval(x)
            self.assertEqual(polling_time, 1_000)

        # Configure watchdog polling for 2s on queue 2
        mac_port.set_pfc_queue_watchdog_polling_interval(2, 2_000)
        polling_time = mac_port.get_pfc_queue_watchdog_polling_interval(2)
        self.assertEqual(polling_time, 2_000)
        mac_port.set_pfc_queue_watchdog_polling_interval(2, 100)
        polling_time = mac_port.get_pfc_queue_watchdog_polling_interval(2)
        self.assertEqual(polling_time, 100)

        # verify each queue has recovery for 0s
        for x in range(8):
            recovery_time = mac_port.get_pfc_queue_watchdog_recovery_interval(x)
            self.assertEqual(recovery_time, 0)

        # Configure watchdog recovery for 1s
        mac_port.set_pfc_watchdog_recovery_interval(1_000)
        recovery_time = mac_port.get_pfc_watchdog_recovery_interval()
        self.assertEqual(recovery_time, 1_000)

        # verify each queue has polling for 1s
        for x in range(8):
            recovery_time = mac_port.get_pfc_queue_watchdog_recovery_interval(x)
            self.assertEqual(recovery_time, 1_000)

        # Configure watchdog recovery for 2s on queue 2
        mac_port.set_pfc_queue_watchdog_recovery_interval(2, 2_000)
        recovery_time = mac_port.get_pfc_queue_watchdog_recovery_interval(2)
        self.assertEqual(recovery_time, 2_000)

        # Enable Watchdog polling
        mac_port.set_pfc_queue_watchdog_enabled(self.tc_value, True)

        # Check that its enabled
        state = mac_port.get_pfc_queue_watchdog_enabled(self.tc_value)
        self.assertEqual(state, True)

        # Check another queue which is disabled
        state = mac_port.get_pfc_queue_watchdog_enabled(self.tc_value + 1)
        self.assertEqual(state, False)

        # Check if the queue is stuck
        state = mac_port.get_pfc_queue_state(self.tc_value)
        self.assertEqual(state, sdk.la_mac_port.pfc_queue_state_e_EMPTY)

        # Send a PFC packet.
        run_and_drop(
            self,
            self.device,
            self.pfc_packet,
            mac_port.get_slice(),
            mac_port.get_ifg(),
            mac_port.get_first_serdes_id())

        # make sure that we received a PFC packet. Also make sure that we don't clear the counter in hw
        counter = mac_port.get_pfc_counter()
        packets, bytes = counter.read(self.tc_value, True, False)
        self.assertEqual(packets, 1)

        # Enable Watchdog polling
        mac_port.set_pfc_queue_watchdog_enabled(self.tc_value, True)

        # Check that its enabled
        state = mac_port.get_pfc_queue_watchdog_enabled(self.tc_value)
        self.assertEqual(state, True)

        # Set the transmit state for this queue to stop transmitting
        mac_port.set_pfc_queue_configured_state(self.tc_value, sdk.la_mac_port.pfc_config_queue_state_e_DROPPING)
        state, counter_allocated = mac_port.get_pfc_queue_configured_state(self.tc_value)
        self.assertEqual(state, sdk.la_mac_port.pfc_config_queue_state_e_DROPPING)
        self.assertEqual(counter_allocated, True)

        drop = mac_port.read_pfc_queue_drain_counter(self.tc_value, False)
        self.assertEqual(drop, 0)

        # Set the queue back to active state
        mac_port.set_pfc_queue_configured_state(self.tc_value, sdk.la_mac_port.pfc_config_queue_state_e_ACTIVE)
        state, counter_allocated = mac_port.get_pfc_queue_configured_state(self.tc_value)
        self.assertEqual(state, sdk.la_mac_port.pfc_config_queue_state_e_ACTIVE)

        # clear the recovery interval
        mac_port.set_pfc_queue_watchdog_recovery_interval(2, 0)
        recovery_time = mac_port.get_pfc_queue_watchdog_recovery_interval(2)
        self.assertEqual(recovery_time, 0)

        # enable watchdog on 4 queues
        for tc in range(0, 4):
            mac_port.set_pfc_queue_watchdog_enabled(tc, True)
        # disable queue on 4 queues
        for tc in range(0, 4):
            mac_port.set_pfc_queue_configured_state(tc, sdk.la_mac_port.pfc_config_queue_state_e_DROPPING)
        # check all queue are dropping
        for tc in range(0, 2):
            state, counter_allocated = mac_port.get_pfc_queue_configured_state(tc)
            self.assertEqual(state, sdk.la_mac_port.pfc_config_queue_state_e_DROPPING)
            self.assertEqual(counter_allocated, True)
        state, counter_allocated = mac_port.get_pfc_queue_configured_state(2)
        self.assertEqual(state, sdk.la_mac_port.pfc_config_queue_state_e_DROPPING)
        self.assertEqual(counter_allocated, False)
        state, counter_allocated = mac_port.get_pfc_queue_configured_state(3)
        self.assertEqual(state, sdk.la_mac_port.pfc_config_queue_state_e_DROPPING)
        self.assertEqual(counter_allocated, False)
        # should be able read all counters
        for tc in range(0, 4):
            drop = mac_port.read_pfc_queue_drain_counter(tc, False)
            self.assertEqual(drop, 0)
        # Reenable the queues
        for tc in range(0, 4):
            mac_port.set_pfc_queue_configured_state(tc, sdk.la_mac_port.pfc_config_queue_state_e_ACTIVE)
        # Read the drop counters again
        for tc in range(0, 4):
            drop = mac_port.read_pfc_queue_drain_counter(tc, False)
            self.assertEqual(drop, 0)
