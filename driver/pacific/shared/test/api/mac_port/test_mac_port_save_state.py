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

from packet_test_utils import *
import unittest
from leaba import sdk
import decor
import sim_utils
import topology as T
import time
import tempfile
import pma_tx_err_helper as pma


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
class save_state_tester(unittest.TestCase):

    def setUp(self):
        self.device = sim_utils.create_device(0)
        slice_id = 1
        ifg_id = 1
        first_serdes_id = 0
        last_serdes_id = 1

        self.root_key = "mac_port_%d_%d_%d" % (slice_id, ifg_id, first_serdes_id)
        self.is_hw_pacific = self.device.ll_device.is_pacific() and decor.is_hw_device()
        self.is_hw_gibraltar = self.device.ll_device.is_gibraltar() and decor.is_hw_device()

        self.max_sm_transition_captures = 4
        self.device.set_int_property(
            sdk.la_device_property_e_MAC_PORT_SAVE_STATE_SM_STATE_TRANSITION_CAPTURES,
            self.max_sm_transition_captures)

        if self.is_hw_pacific:
            self.max_serdes_debug_snapshots = 1
            self.device.set_int_property(
                sdk.la_device_property_e_MAC_PORT_SAVE_STATE_SERDES_DEBUG_SNAPSHOTS,
                self.max_serdes_debug_snapshots)
        port_speed = sdk.la_mac_port.port_speed_e_E_100G
        if T.is_matilda_model(self.device):
            port_speed = sdk.la_mac_port.port_speed_e_E_50G
        self.mp = self.device.create_mac_port(
            slice_id,
            ifg_id,
            first_serdes_id,
            last_serdes_id,
            port_speed,
            sdk.la_mac_port.fc_mode_e_NONE,
            sdk.la_mac_port.fec_mode_e_RS_KR4)
        self.mp.set_loopback_mode(sdk.la_mac_port.loopback_mode_e_SERDES)
        self.mp.activate()

        if self.is_hw_pacific:
            pma_tx_err = pma.pma_tx_err_helper(self.device)

            # inject errors into SERDES loopback port to force tuning failures
            pma_tx_err.pma_tx_err_inject(slice_id, ifg_id, first_serdes_id, enable=1, pattern=0xffff, nof_words=1, period=1 * 1e-3)

            # SM transition from TUNED -> TUNING means failed tune which captures a snapshot
            self.wait_for_state(sdk.la_mac_port.state_e_TUNED)
            self.wait_for_state(sdk.la_mac_port.state_e_TUNING)

            # disable error injection
            pma_tx_err.pma_tx_err_inject(slice_id, ifg_id, first_serdes_id, enable=0, pattern=0xffff, nof_words=1, period=1 * 1e-3)
        else:
            # only checking state machine transitions
            self.wait_for_state(sdk.la_mac_port.state_e_LINK_UP)

    def tearDown(self):
        self.device.tearDown()

    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    def test_save_state(self):
        tmp_fd = tempfile.NamedTemporaryFile(suffix=".json")

        info_type = sdk.la_mac_port.port_debug_info_e_ALL
        self.mp.save_state(info_type, tmp_fd.name)

        # verify file is created
        self.check_file_exists(tmp_fd.name)

        # json tree contains entire JSON structure
        json_tree = self.parse_json(tmp_fd.name)

        # check to see if mac_port tree is included
        self.check_root_keys(json_tree)
        mac_port_tree = json_tree[self.root_key]

        # verify mac level keys included
        self.check_mac_keys(mac_port_tree)

        # verify and test queued MAC_PORT state machine captures
        self.check_state_transitions(mac_port_tree)

        if self.is_hw_pacific:
            self.check_pacific_keys(mac_port_tree)
            self.check_serdes_debug_snapshots(mac_port_tree)

        if self.is_hw_gibraltar:
            self.check_gibraltar_keys(mac_port_tree)

    # Pacific Helper Functions
    def check_pacific_keys(self, json_tree):
        pacific_keys = [
            "serdes_soft_state",
            "tx_info",
            "rx_info",
            "serdes_failed_tunes"
        ]
        self.check_json_keys(json_tree, pacific_keys)

    def check_serdes_debug_snapshots(self, json_tree):
        key = 'serdes_failed_tunes'

        self.check_fixed_queue(
            sdk.la_device_property_e_MAC_PORT_SAVE_STATE_SERDES_DEBUG_SNAPSHOTS,
            key,
            self.max_serdes_debug_snapshots)

        serdes_snapshot_keys = [
            "serdes_id",
            "cause",
            "timestamp",
            "ctle",
            "rxFFE",
            "vos",
            "vernierDelay",
            "dfeTAP",
            "eyeHeights",
            "state",
            "status",
            "frequency_lock",
            "delta_cal_fail",
            "signal_ok_enable"
        ]

        serdes_debug_snapshots_list = json_tree[key]
        for snapshot in serdes_debug_snapshots_list:
            # each snapshot has a JSON object for each SerDes
            for serdes_key in snapshot:
                serdes_tree = snapshot[serdes_key]
                self.check_json_keys(serdes_tree, serdes_snapshot_keys)

    # Gibraltar Helper Functions
    def check_gibraltar_keys(self, json_tree):
        gibraltar_keys = [
            "serdes_status",
            "link_config",
            "mcu_status",
        ]
        self.check_json_keys(json_tree, gibraltar_keys)

    # Common Helper Functions
    def check_mac_keys(self, json_tree):
        mac_keys = [
            "mac_state_histogram",
            "mac_port_config",
            "fec_status",
            "mac_port_status",
            "mib_counters",
            "state_transition_history"
        ]
        self.check_json_keys(json_tree, mac_keys)

    def check_fixed_queue(self, device_property, key, max_value, min_value=0):
        # we need a new save_state file to view our changes
        fd = tempfile.NamedTemporaryFile(suffix=".json")

        # verify that changing device_property applies changes to queue
        # decrement by one until we get a max_value of min_value
        while (max_value > min_value):
            self.device.set_int_property(device_property, max_value)
            self.mp.save_state(sdk.la_mac_port.port_debug_info_e_MAC_STATUS, fd.name)

            list_array = self.parse_json(fd.name)[self.root_key][key]
            list_size = len(list_array)

            self.assertEqual(list_size, max_value, "Queue did not remove entry")

            # decrease max size and update
            max_value -= 1

        # apply a max_value of min_value
        self.device.set_int_property(device_property, max_value)

        self.mp.save_state(sdk.la_mac_port.port_debug_info_e_MAC_STATUS, fd.name)

        if min_value == 0:
            # check to verify key is no longer in JSON tree
            mac_port_json = self.parse_json(fd.name)[self.root_key]
            self.assertFalse(key in mac_port_json)
        else:
            list_array = self.parse_json(fd.name)[self.root_key][key]
            list_size = len(list_array)
            self.assertEqual(list_size, min_value, "Queue size is not min_value")

    def check_state_transitions(self, json_tree):
        key = 'state_transition_history'

        self.check_fixed_queue(
            sdk.la_device_property_e_MAC_PORT_SAVE_STATE_SM_STATE_TRANSITION_CAPTURES,
            key,
            self.max_sm_transition_captures, 2)

        sm_capture_keys = [
            "new_state",
            "timestamp"
        ]

        sm_capture_list = json_tree[key]
        for sm_transition_tree in sm_capture_list:
            self.check_json_keys(sm_transition_tree, sm_capture_keys)

    def wait_for_state(self, state):
        timeout = 20  # in seconds
        start_waiting_epoch = time.time()

        state_map = {
            sdk.la_mac_port.state_e_TUNED: "TUNED",
            sdk.la_mac_port.state_e_TUNING: "TUNING",
            sdk.la_mac_port.state_e_LINK_UP: "LINK_UP",
        }

        while self.mp.get_state() != state:
            curr_epoch = time.time()
            epoch_since_start = curr_epoch - start_waiting_epoch
            self.assertFalse(epoch_since_start > timeout, "Timeout waiting for MAC_PORT to enter %s state" % (state_map[state]))

    def check_file_exists(self, filename):
        file_exist = os.path.isfile(filename)
        self.assertTrue(file_exist, 'MAC_PORT save state not created')

    def check_json_keys(self, json_tree, keys):
        for key in keys:
            self.assertTrue(key in json_tree, "Key '%s' not found" % (key))

    def check_root_keys(self, json_tree):
        self.assertTrue(self.root_key in json_tree, "Key '%s' not found" % (self.root_key))

        link_down_key = self.root_key + ".link_down_histogram"
        self.assertTrue(link_down_key in json_tree, "Key '%s' not found" % (link_down_key))

    def parse_json(self, filename):
        fd = open(filename)
        tree = json.load(fd)
        fd.close()
        return tree


if __name__ == '__main__':
    unittest.main()
