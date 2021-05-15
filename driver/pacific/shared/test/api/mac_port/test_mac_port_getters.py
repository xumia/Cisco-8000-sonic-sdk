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
import decor
import tempfile
import os
import json
from mac_port_base import *


verbose = 0

SLICE_ID = 2
IFG_ID = 0
FIRST_SERDES_ID = 8
LAST_SERDES_ID = 11


@unittest.skipIf(decor.is_hw_device(), "Was excluded in HW sanity Makefile.")
class mac_port_getters(mac_port_base):

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    def test_mac_port_getters(self):
        speed = sdk.la_mac_port.port_speed_e_E_100G
        fc_mode = sdk.la_mac_port.fc_mode_e_NONE
        fec_mode = sdk.la_mac_port.fec_mode_e_RS_KR4

        if verbose >= 1:
            sdk.la_set_logging_level(self.dev_id, sdk.la_logger_component_e_API, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_level(self.dev_id, sdk.la_logger_component_e_HLD, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_level(self.dev_id, sdk.la_logger_component_e_MAC_PORT, sdk.la_logger_level_e_DEBUG)

        self.device.create_mac_port(SLICE_ID, IFG_ID, FIRST_SERDES_ID, LAST_SERDES_ID, speed, fc_mode, fec_mode)

        port = self.device.get_mac_port(SLICE_ID, IFG_ID, FIRST_SERDES_ID)

        # Normal getters
        val = port.get_serdes_tuning_mode()
        val = port.get_serdes_continuous_tuning_enabled()
        val = port.get_serdes_continuous_tuning_enabled()
        val = port.get_port_signal_ok()
        val = port.get_serdes_signal_ok(0)
        val = port.get_tune_status()
        val = port.is_an_capable()
        val = port.get_an_enabled()
        val = port.get_state_histogram(False)
        val = port.get_link_down_histogram(False)
        val = port.get_state()
        val = port.get_speed()
        val = port.get_serdes_speed()
        val = port.get_fec_mode()
        val = port.get_fc_mode(sdk.la_mac_port.fc_direction_e_BIDIR)
        val = port.get_rs_fec_debug_enabled()
        val = port.get_min_packet_size()
        val = port.get_max_packet_size()
        gap_len, gap_tx_bytes = port.get_ipg()
        val = port.get_loopback_mode()
        val = port.get_link_management_enabled()
        val = port.get_pcs_test_mode()
        val = port.get_pma_test_mode()
        val = port.get_serdes_test_mode(sdk.la_serdes_direction_e_TX)
        val = port.get_ostc_quantizations()
        val = port.get_default_port_tc()
        val = port.get_port_tc_custom_protocols()
        val = port.get_serdes_parameters(FIRST_SERDES_ID // 8)
        val = port.get_port_tc_tpids()

        if not decor.is_asic3():
            val, bitmap = port.get_pfc_enabled()
            counter = port.get_pfc_counter()
            val = port.get_pfc_quanta()

        val = port.get_pfc_queue_watchdog_enabled(0)
        val = port.get_pfc_watchdog_polling_interval()
        state, counter_allocated = port.get_pfc_queue_configured_state(0)

        val = port.get_fec_bypass_mode()

        # Getters that are expected to return status other than LA_STATUS_SUCCESS
        self.expect_runtime_error(sdk.la_status_e_E_INVAL, port.get_pfc_queue_state, 0)

        if not decor.is_asic3():
            self.expect_runtime_error(
                sdk.la_status_e_E_NOTFOUND,
                port.get_port_tc_for_fixed_protocol,
                sdk.la_mac_port.tc_protocol_e_IPV6,
                0)
        self.expect_runtime_error(
            sdk.la_status_e_E_NOTFOUND,
            port.get_serdes_parameter,
            0,
            sdk.la_mac_port.serdes_param_stage_e_ACTIVATE,
            sdk.la_mac_port.serdes_param_e_ELECTRICAL_IDLE_THRESHOLD)
        self.expect_runtime_error(sdk.la_status_e_E_NOTIMPLEMENTED, port.get_preamble_compression_enabled)
        self.expect_runtime_error(sdk.la_status_e_E_NOTFOUND, port.get_port_tc_layer, 0, sdk.la_mac_port.tc_protocol_e_IPV6)
        self.expect_runtime_error(
            sdk.la_status_e_E_NOTFOUND,
            port.get_port_tc_for_custom_protocol,
            0,
            sdk.la_mac_port.tc_protocol_e_IPV6)

        # TODO: la_uint128_t getters are not exposed to SWIG properly
        self.expect_type_error(port.get_pcs_test_seed)
        self.expect_type_error(port.get_pma_test_seed)

        # Check read_xxx() API
        val = port.read_serdes_status(FIRST_SERDES_ID // 8)
        val = port.read_mac_status()
        val = port.read_mac_pcs_lane_mapping()
        val = port.read_mib_counters(False)
        val = port.read_rs_fec_debug_counters()
        val = port.read_rs_fec_symbol_errors_counters()
        val = port.read_ostc_counter(0)
        val = port.read_counter(False, port.counter_e_PCS_TEST_ERROR)
        val = port.read_pma_test_ber()
        val = port.read_serdes_test_ber()
        self.expect_runtime_error(sdk.la_status_e_E_INVAL, port.read_pfc_queue_drain_counter, 0, False)

        # Check save_state
        if not decor.is_asic3():
            self.verify_mac_port_state(port)

        self.verify_mac_port_tpids(port)

    def expect_runtime_error(self, la_status, func, *args):
        try:
            val = func(*args)
        except sdk.BaseException as error:
            self.assertEqual(error.args[0], la_status)

    def expect_type_error(self, func, *args):
        try:
            val = func(*args)
        except TypeError as error:
            pass

    def verify_mac_port_tpids(self, port):
        OSTC_NUM_TPIDS = 4
        # Verify TPIDs are empty
        tpids = port.get_port_tc_tpids()
        for tpid in tpids:
            if tpid != 0:
                port.remove_port_tc_tpid(tpid)

        # Add all TPIDs available
        for tpid in range(1, OSTC_NUM_TPIDS):
            port.add_port_tc_tpid(tpid)

        # Verify all TPIDs are present
        tpids = port.get_port_tc_tpids()
        self.assertTrue(1 in tpids)
        self.assertTrue(2 in tpids)
        self.assertTrue(3 in tpids)

        for tpid in range(1, OSTC_NUM_TPIDS):
            port.remove_port_tc_tpid(tpid)

        # Verify we have removed all TPIDs
        tpids = port.get_port_tc_tpids()
        self.assertFalse(1 in tpids)
        self.assertFalse(2 in tpids)
        self.assertFalse(3 in tpids)

    def verify_mac_port_state(self, port):
        state = self.save_mac_port_state(port)
        if verbose >= 1:
            print('mac_port saved state:', state)

        keys = list(state.keys())
        root_key = keys[0]
        self.assertEqual(root_key, 'mac_port_%d_%d_%d' % (SLICE_ID, IFG_ID, FIRST_SERDES_ID))
        self.assertEqual(state[root_key]['mac_port_config']['fec_mode'], 'RS_KR4')
        self.assertEqual(state[root_key]['mac_port_config']['serdes_speed'], 'E_25G')
        self.assertEqual(state[root_key]['mac_port_config']['num_of_serdes'], LAST_SERDES_ID - FIRST_SERDES_ID + 1)
        self.assertEqual(state[root_key]['mac_port_soft_state']['port_slice_mode'], 'NETWORK')
        self.assertEqual(state[root_key]['mac_port_soft_state']['port_state'], 'PRE_INIT')


if __name__ == '__main__':
    unittest.main()
