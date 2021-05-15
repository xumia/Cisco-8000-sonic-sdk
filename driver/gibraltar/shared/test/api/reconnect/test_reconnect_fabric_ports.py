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

from packet_test_utils import *
import unittest
from leaba import sdk
import rpfo
import topology
from sdk_test_case_base import *
import sim_utils
import decor

import collections
import re
import json
import os
import tempfile

verbose = 0

FE_DEVICE_ID = 280
FE_RX_SLICE = 2
FE_RX_IFG = 0
FE_RX_SERDES_FIRST = 4
FE_RX_SERDES_LAST = FE_RX_SERDES_FIRST + 1

FE_TX_SLICE = 4
FE_TX_IFG = 1
FE_TX_SERDES_FIRST = 2
FE_TX_SERDES_LAST = FE_TX_SERDES_FIRST + 1

INGRESS_DEVICE_ID = 1
INGRESS_RX_SLICE = 2

EGRESS_DEVICE_ID = 10
EGRESS_TX_SLICE = 2
EGRESS_TX_IFG = 0
EGRESS_TX_SERDES_FIRST = 16

RX, TX = 0, 1
if decor.is_gibraltar():
    FE_SERDES_PARAMS = {
        RX: [
            {
                'idx': 0,
                'stage': sdk.la_mac_port.serdes_param_stage_e_ACTIVATE,
                'param': sdk.la_mac_port.serdes_param_e_DATAPATH_TX_GRAY_MAP,
                'mode': sdk.la_mac_port.serdes_param_mode_e_FIXED,
                'value': 0
            },
            {
                'idx': 0,
                'stage': sdk.la_mac_port.serdes_param_stage_e_ACTIVATE,
                'param': sdk.la_mac_port.serdes_param_e_DATAPATH_TX_GRAY_MAP,
                'mode': sdk.la_mac_port.serdes_param_mode_e_FIXED,
                'value': 0
            },
        ],
        TX: [
            {
                'idx': 0,
                'stage': sdk.la_mac_port.serdes_param_stage_e_ACTIVATE,
                'param': sdk.la_mac_port.serdes_param_e_DATAPATH_TX_GRAY_MAP,
                'mode': sdk.la_mac_port.serdes_param_mode_e_FIXED,
                'value': 1
            },
        ]
    }
else:
    FE_SERDES_PARAMS = {
        RX: [
            {
                'idx': 0,
                'stage': sdk.la_mac_port.serdes_param_stage_e_PRE_PCAL,
                'param': sdk.la_mac_port.serdes_param_e_RX_CTLE_SHORT_CHANNEL_EN,
                'mode': sdk.la_mac_port.serdes_param_mode_e_FIXED,
                'value': 0
            },
            {
                'idx': 0,
                'stage': sdk.la_mac_port.serdes_param_stage_e_PRE_PCAL,
                'param': sdk.la_mac_port.serdes_param_e_RX_CTLE_SHORT_CHANNEL_EN,
                'mode': sdk.la_mac_port.serdes_param_mode_e_STATIC,
                'value': 0
            },
        ],
        TX: [
            {
                'idx': 0,
                'stage': sdk.la_mac_port.serdes_param_stage_e_PRE_ICAL,
                'param': sdk.la_mac_port.serdes_param_e_RX_CTLE_SHORT_CHANNEL_EN,
                'mode': sdk.la_mac_port.serdes_param_mode_e_STATIC,
                'value': 1
            },
        ]
    }


# Ignore histograms and counters, as they are zeros after RPFO.
IGNORE_KEYS = [
    r'link_down_histogram',
    r'mac_state_histogram',
    r'mac_port_soft_state:pcal_stop_rx_disabled',  # TODO: should be no diff in pcal_stop_rx_disabled
    r'mac_port_soft_state:tune_with_pcs_lock',
    r'mac_port_soft_state:bad_tunes',
    r'ctle_info',
    r'dfe_state_info',
    r'serdes_failed_tunes',
    r'state_transition_history',
    r'anlt_snapshots',
    r'mcu_status',
    r'histogram:index_0:graph',
    r'fec_status',
    r'serdes_status:index_0_PLL:PLL_LOCK_TIME_MS',
    r'serdes_status:index_1_PLL:PLL_LOCK_TIME_MS'
]

SLEEP_AFTER_ACTIVATE = 3
SLEEP_AFTER_STOP = 1


@unittest.skipIf(decor.is_gibraltar() and not decor.is_hw_device(), "Test is disabled for GB NSIM")
@unittest.skipIf(decor.is_asic4(), "No FE for Asic4.")
@unittest.skipIf(decor.is_asic5(), "No FE for Asic5.")
@unittest.skipIf(decor.is_asic3(), "No FE for Asic3")
class test_reconnect_fabric_ports(sdk_test_case_base):
    @staticmethod
    def device_config_func(device, state):
        if state == sdk.la_device.init_phase_e_DEVICE:
            for sid in range(topology.NUM_SLICES_PER_DEVICE):
                device.set_fabric_slice_clos_direction(sid, sdk.la_clos_direction_e_DOWN)

    @classmethod
    def setUpClass(cls):
        super(test_reconnect_fabric_ports, cls).setUpClass(slice_modes=sim_utils.FABRIC_ELEMENT_DEV,
                                                           device_config_func=test_reconnect_fabric_ports.device_config_func)
        cls.device.crit_fd, cls.device.norm_fd = cls.device.open_notification_fds(sdk.LA_NOTIFICATION_MASK_ALL)

    def setUp(self):
        if verbose >= 1:
            sdk.la_set_logging_level(INGRESS_DEVICE_ID, sdk.la_logger_component_e_RECONNECT, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_level(INGRESS_DEVICE_ID, sdk.la_logger_component_e_MAC_PORT, sdk.la_logger_level_e_DEBUG)
            sdk.la_set_logging_level(INGRESS_DEVICE_ID, sdk.la_logger_component_e_SERDES, sdk.la_logger_level_e_DEBUG)

    def tearDown(self):
        self.device.clear_device()

    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_fabric_ports_persistency_across_reconnect(self):
        '''
            Test flow:
                1. Pre-RPFO
                    - Verify default device level settings.
                    - Modify device level values.
                    - Create RX and TX fabric ports
                    - Verify default port-level settings.
                    - Modify port-level settings.
                2. RPFO
                    - disable write-to-HW, destroy device, create new device
                3. Post-RPFO
                    - Verify that ports and all modified settings are restored
                4. Stop/activate
                5. Destroy/create
        '''
        # Validate the default
        property_val = self.device.get_int_property(sdk.la_device_property_e_MINIMUM_FABRIC_PORTS_FOR_CONNECTIVITY)
        self.assertEqual(property_val, 1)

        # Write new value
        new_property_val = 3
        self.device.set_int_property(sdk.la_device_property_e_MINIMUM_FABRIC_PORTS_FOR_CONNECTIVITY, new_property_val)

        # Validate the default fe_fabric_reachability
        fe_reachability_enabled = self.device.get_fe_fabric_reachability_enabled()
        self.assertEqual(fe_reachability_enabled, True)

        # Enable SW-managed min-links-per-lc, and modify the default number of min links
        self.device.set_bool_property(sdk.la_device_property_e_ENABLE_FE_PER_DEVICE_MIN_LINKS, True)
        min_links_per_lc = self.device.get_minimum_fabric_links_per_lc(EGRESS_DEVICE_ID)
        min_links_per_lc_new = 2
        self.assertNotEqual(min_links_per_lc, min_links_per_lc_new)
        self.device.set_minimum_fabric_links_per_lc(EGRESS_DEVICE_ID, min_links_per_lc_new)

        # Flip serdes polarity
        fe_rx_polarity = self.device.get_serdes_polarity_inversion(
            FE_RX_SLICE, FE_RX_IFG, FE_RX_SERDES_FIRST, sdk.la_serdes_direction_e_RX)
        fe_rx_polarity_new = not fe_rx_polarity
        self.device.set_serdes_polarity_inversion(
            FE_RX_SLICE,
            FE_RX_IFG,
            FE_RX_SERDES_FIRST,
            sdk.la_serdes_direction_e_RX,
            fe_rx_polarity_new)

        fe_tx_polarity = self.device.get_serdes_polarity_inversion(
            FE_TX_SLICE, FE_TX_IFG, FE_TX_SERDES_FIRST, sdk.la_serdes_direction_e_TX)
        fe_tx_polarity_new = not fe_tx_polarity
        self.device.set_serdes_polarity_inversion(
            FE_TX_SLICE,
            FE_TX_IFG,
            FE_TX_SERDES_FIRST,
            sdk.la_serdes_direction_e_TX,
            fe_tx_polarity_new)

        # Create rx fabric port
        rx_fabric_mac_port = topology.fabric_mac_port(
            self,
            self.device,
            FE_RX_SLICE,
            FE_RX_IFG,
            FE_RX_SERDES_FIRST,
            FE_RX_SERDES_LAST)
        rx_fabric_port = topology.fabric_port(self, self.device, rx_fabric_mac_port)

        # Create tx fabric port
        tx_fabric_mac_port = topology.fabric_mac_port(
            self,
            self.device,
            FE_TX_SLICE,
            FE_TX_IFG,
            FE_TX_SERDES_FIRST,
            FE_TX_SERDES_LAST)
        tx_fabric_port = topology.fabric_port(self, self.device, tx_fabric_mac_port)

        mac_ports = {RX: rx_fabric_mac_port.hld_obj, TX: tx_fabric_mac_port.hld_obj}

        self.print_serdes_state(mac_ports[TX], 'TX state after create')

        # Manually set reachability to egress device
        self.device.set_bool_property(sdk.la_device_property_e_LC_ADVERTISE_DEVICE_ON_FABRIC_MODE, False)
        reachable_devices = [EGRESS_DEVICE_ID]
        tx_fabric_port.hld_obj.set_reachable_lc_devices(reachable_devices)

        ret = tx_fabric_port.hld_obj.get_reachable_lc_devices()
        # Reachable devices is retrieved from "volatile" dmc.frm.fabric_routing_table
        self.assertEqual(ret, reachable_devices)

        # Set serdes parameters
        for i in [RX, TX]:
            self.do_set_serdes_params(mac_ports[i], FE_SERDES_PARAMS[i])

        # Change ports states
        mac_ports[TX].set_loopback_mode(sdk.la_mac_port.loopback_mode_e_SERDES)
        for i in [RX, TX]:
            mac_ports[i].activate()

        time.sleep(SLEEP_AFTER_ACTIVATE)

        # On real HW, if there is no loopback we don't expect that the port will
        # come up or even get a PCS lock, but it can trigger tune.
        expect_rx_is_up = not decor.is_hw_device()
        expected_tx_state = sdk.la_mac_port.state_e_LINK_UP
        rx_state = mac_ports[RX].get_state()
        if expect_rx_is_up:
            self.assertEqual(rx_state, sdk.la_mac_port.state_e_LINK_UP)
        else:
            self.assertLess(rx_state, sdk.la_mac_port.state_e_PCS_LOCK)
            self.assertGreater(rx_state, sdk.la_mac_port.state_e_ACTIVE)
        self.assertEqual(mac_ports[TX].get_state(), expected_tx_state)

        self.print_serdes_state(mac_ports[TX], 'TX state after activate()')

        mac_ports[TX].stop()
        time.sleep(SLEEP_AFTER_STOP)
        self.print_serdes_state(mac_ports[TX], 'TX state after stop()')

        mac_ports[TX].activate()
        time.sleep(SLEEP_AFTER_ACTIVATE)
        self.print_serdes_state(mac_ports[TX], 'TX state after activate()')

        detailed_state_before = {}
        for i in [RX, TX]:
            detailed_state_before[i] = save_mac_port_state(mac_ports[i])

        # RPFO start
        topology_objects_to_destroy = [tx_fabric_port, tx_fabric_mac_port, rx_fabric_port, rx_fabric_mac_port]
        rpfo.rpfo(self.device, topology_objects_to_destroy, [])
        # RPFO end

        # Wait for the mac-port state machine to kick in
        time.sleep(5)

        mac_ports = self.device.get_objects(sdk.la_object.object_type_e_MAC_PORT)
        fabric_ports = self.device.get_objects(sdk.la_object.object_type_e_FABRIC_PORT)
        self.assertEqual(len(mac_ports), 2)
        self.assertEqual(len(fabric_ports), 2)
        self.print_serdes_state(mac_ports[TX], 'TX state after RPFO')

        rx_state = mac_ports[RX].get_state()
        detailed_state_after = {}
        for i in [RX, TX]:
            detailed_state_after[i] = save_mac_port_state(mac_ports[i])

        # Verify that fabric ports and their state is restored after reconnect:
        # - MINIMUM_FABRIC_PORTS_FOR_CONNECTIVITY is set to the new value
        # - fe_fabric_reachability is True (i.e. different from the default initialization of a boolean to False)
        # - we still have 2 mac and fabric ports

        property_val = self.device.get_int_property(sdk.la_device_property_e_MINIMUM_FABRIC_PORTS_FOR_CONNECTIVITY)
        fe_reachability_enabled = self.device.get_fe_fabric_reachability_enabled()
        fe_rx_polarity = self.device.get_serdes_polarity_inversion(
            FE_RX_SLICE, FE_RX_IFG, FE_RX_SERDES_FIRST, sdk.la_serdes_direction_e_RX)
        fe_tx_polarity = self.device.get_serdes_polarity_inversion(
            FE_TX_SLICE, FE_TX_IFG, FE_TX_SERDES_FIRST, sdk.la_serdes_direction_e_TX)
        fe_per_device_min_links_enabled = self.device.get_bool_property(sdk.la_device_property_e_ENABLE_FE_PER_DEVICE_MIN_LINKS)
        min_links_per_lc = self.device.get_minimum_fabric_links_per_lc(EGRESS_DEVICE_ID)

        self.assertEqual(property_val, new_property_val)
        self.assertEqual(fe_rx_polarity, fe_rx_polarity_new)
        self.assertEqual(fe_tx_polarity, fe_tx_polarity_new)
        self.assertEqual(fe_reachability_enabled, True)
        self.assertEqual(fe_per_device_min_links_enabled, True)
        self.assertEqual(min_links_per_lc, min_links_per_lc_new)

        if expect_rx_is_up:
            self.assertEqual(rx_state, sdk.la_mac_port.state_e_LINK_UP)
        else:
            self.assertLess(rx_state, sdk.la_mac_port.state_e_PCS_LOCK)
            self.assertGreater(rx_state, sdk.la_mac_port.state_e_ACTIVE)
        self.assertEqual(mac_ports[TX].get_state(), expected_tx_state)
        for i in [RX, TX]:
            self.do_verify_serdes_params(mac_ports[i], FE_SERDES_PARAMS[i])

        # Verify diff in mac_state before VS after RPFO
        #
        self.verify_diff_mac_port_state('RX diff', detailed_state_before[RX], detailed_state_after[RX], ignore_keys=IGNORE_KEYS)
        self.verify_diff_mac_port_state('TX diff', detailed_state_before[TX], detailed_state_after[TX], ignore_keys=IGNORE_KEYS)

        # Verify that SerDes IP is accessible
        for i in [RX, TX]:
            mac_ports[i].stop()
            self.assertEqual(mac_ports[i].get_state(), sdk.la_mac_port.state_e_INACTIVE)

        # Give a chance for pollers to spin a few rounds.
        # If anything nasty happens, the test will fail.
        print('Sleep for %d seconds after stop()' % SLEEP_AFTER_STOP)
        time.sleep(SLEEP_AFTER_STOP)
        self.print_serdes_state(mac_ports[TX], 'TX state after RPFO + stop + sleep')

        # Verify that mac ports can be activated after they are stopped
        for i in [RX, TX]:
            mac_ports[i].activate()

        print('Sleep for %d seconds after activate()' % SLEEP_AFTER_ACTIVATE)
        time.sleep(SLEEP_AFTER_ACTIVATE)
        self.print_serdes_state(mac_ports[TX], 'TX state after RPFO + stop + activate + sleep')

        for i in [RX, TX]:
            self.device.destroy(fabric_ports[i])
            self.device.destroy(mac_ports[i])

    def do_set_serdes_params(self, fabric_mac_port, serdes_params):
        for p in serdes_params:
            fabric_mac_port.set_serdes_parameter(p['idx'], p['stage'], p['param'], p['mode'], p['value'])

    def do_verify_serdes_params(self, fabric_mac_port, serdes_params):
        # set_serdes_param() may be called multiple times for the same key=(idx,stage,param).
        # We expect get_serdes_param() to return values from the last set_...()
        expected_params = {}
        for p in serdes_params:
            expected_params[(p['idx'], p['stage'], p['param'])] = (p['mode'], p['value'])
        for key in expected_params:
            # expected key/value
            value = expected_params[key]
            idx, stage, param, mode, value = list(key)[0], list(key)[1], list(key)[2], list(value)[0], list(value)[1]

            # get actual value
            mode_out, value_out = fabric_mac_port.get_serdes_parameter(idx, stage, param)

            # compare expected vs actual
            self.assertEqual(mode, mode_out)
            self.assertEqual(value, value_out)

    def print_serdes_state(self, mac_port, msg):
        if verbose == 0:
            return
        print(msg)
        if self.device.device.get_ll_device().is_pacific():
            import aaplcli
            aapl = self.device.get_ifg_aapl_handler(mac_port.get_slice(), mac_port.get_ifg())
            aaplcli.avago_serdes_state_dump(aapl, 3)

    def verify_diff_mac_port_state(self, msg, state0, state1, ignore_keys=None):
        diff = diff_mac_port_state(state0, state1)
        print(msg, ': all:', diff)

        if ignore_keys:
            regex = re.compile('|'.join(ignore_keys))
            diff_filtered = {}
            tmp = [diff_filtered.update({key: diff[key]}) for key in diff if not re.findall(regex, key)]
            diff = diff_filtered
            print(msg, ': filtered:', diff)

        self.assertEqual(len(diff), 0)


def save_mac_port_state(mac_port):
    # Create a temporary file for storing mac_port state
    fd, fname = tempfile.mkstemp(text=True)
    mac_port.save_state(mac_port.port_debug_info_e_ALL, fname)
    with open(fname) as json_file:
        mac_port_state = json.load(json_file)
    # Delete the tempfile file
    os.unlink(fname)
    return mac_port_state


def flatten(d, parent_key='', sep=':'):
    items = []
    for k, v in d.items():
        new_key = parent_key + sep + k if parent_key else k
        if isinstance(v, collections.MutableMapping):
            items.extend(flatten(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def diff_mac_port_state(state0, state1):
    flat0 = flatten(state0)
    flat1 = flatten(state1)
    keys0 = set(flat0)  # extract dictionary keys and convert them to a 'set'
    keys1 = set(flat1)  # extract dictionary keys and convert them to a 'set'
    assert len(keys0) == len(flat0.keys()), 'flattened keys should be unique'
    assert len(keys1) == len(flat1.keys()), 'flattened keys should be unique'

    diff = {}

    # Keys that exist both in 0 and 1 - store only keys where value0 != value1
    common_keys = keys0.intersection(keys1)
    diff_keys = [key for key in common_keys if flat0[key] != flat1[key]]
    for key in diff_keys:
        diff[key] = [flat0[key], flat1[key]]

    # Keys that exist only in 0 - append everything to `diff`.
    diff_keys = keys0.difference(keys1)
    for key in diff_keys:
        diff[key] = [flat0[key], None]

    # Keys that exist only in 1 - append everything to `diff`.
    diff_keys = keys1.difference(keys0)
    for key in diff_keys:
        diff[key] = [None, flat1[key]]

    return diff


if __name__ == '__main__':
    unittest.main()
