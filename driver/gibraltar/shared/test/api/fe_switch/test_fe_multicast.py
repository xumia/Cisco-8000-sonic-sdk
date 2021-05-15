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
from scapy.all import *
import unittest
from leaba import sdk
from leaba import hldcli
import decor
import sim_utils
import topology as T
from sdk_test_case_base import *
import time

FE_DEVICE_ID = 280

FE_RX_SLICE = 2
FE_RX_IFG = 0
FE_RX_SERDES_FIRST = 4
FE_RX_SERDES_LAST = FE_RX_SERDES_FIRST + 1

OUT_LC_SPECS = [
    {
        'dev_id': 10,
        'ports': [
            {'slice': 1, 'ifg': 0, 'pif': 0},
            {'slice': 1, 'ifg': 1, 'pif': 4},
            {'slice': 1, 'ifg': 1, 'pif': 8},
        ]
    },
    {
        'dev_id': 20,
        'ports': [
            {'slice': 3, 'ifg': 0, 'pif': 2},
            {'slice': 3, 'ifg': 0, 'pif': 6},
            {'slice': 4, 'ifg': 1, 'pif': 10},
            {'slice': 4, 'ifg': 1, 'pif': 12},
        ]
    }
]

INGRESS_DEVICE_ID = 1
INGRESS_RX_SLICE = 2
MC_TEST_THRESHOLD = 4096


@unittest.skipIf(decor.is_auto_warm_boot_enabled(), "WB fails for FE mode")
@unittest.skipIf(decor.is_asic4(), "FE mode is not supported on PL")
@unittest.skipIf(decor.is_asic5(), "Test is not applicable to AR")
@unittest.skipIf(decor.is_matilda(), "Matilda does not support Linecard and Fabric modes. Irrelevant test.")
@unittest.skipIf(decor.is_asic3(), "FE mode is not supported on GR")
class test_fe_multicast(sdk_test_case_base):

    mc_groups = dict()

    @staticmethod
    def device_config_func(device, state):
        if state == sdk.la_device.init_phase_e_DEVICE:
            for sid in range(T.NUM_SLICES_PER_DEVICE):
                device.set_fabric_slice_clos_direction(sid, sdk.la_clos_direction_e_DOWN)
        elif state == sdk.la_device.init_phase_e_TOPOLOGY:
            device.set_bool_property(sdk.la_device_property_e_LC_ADVERTISE_DEVICE_ON_FABRIC_MODE, False)

    @classmethod
    def setUpClass(cls):
        super(test_fe_multicast, cls).setUpClass(slice_modes=sim_utils.FABRIC_ELEMENT_DEV,
                                                 device_config_func=test_fe_multicast.device_config_func)

    def setUp(self):
        self.add_lc_devices()

    def tearDown(self):
        self.device.clear_device()

    def rpfo(self, uut_device, topology_objects_to_destroy, la_objects_to_destroy):
        print('---- RPFO start ----')

        dev_id = uut_device.get_id()

        # Stop HW access, stop interrupt handling, pollers and state machines
        uut_device.device.disconnect()

        if uut_device.crit_fd and uut_device.norm_fd:
            uut_device.device.close_notification_fds()

        # Destroy objects, avoid memory leaks
        for obj in topology_objects_to_destroy:
            obj.destroy()
        for obj in la_objects_to_destroy:
            uut_device.device.destroy(obj)

        # Destroy la_device
        sdk.la_destroy_device(uut_device.device)

        print('---- RPFO device destroyed, creating new device ----')

        uut_device.device = sdk.la_create_device(uut_device.device_path, dev_id)
        uut_device.ll_device = uut_device.device.get_ll_device()
        uut_device.crit_fd, uut_device.norm_fd = uut_device.device.open_notification_fds(sdk.LA_NOTIFICATION_MASK_ALL)

        # Reconnect
        uut_device.set_bool_property(sdk.la_device_property_e_RECONNECT_IGNORE_IN_FLIGHT, True)
        uut_device.device.reconnect()

        print('---- RPFO done ----')

    def add_lc_devices(self):
         # Create rx fabric port
        rx_fabric_mac_port = T.fabric_mac_port(
            self,
            self.device,
            FE_RX_SLICE,
            FE_RX_IFG,
            FE_RX_SERDES_FIRST,
            FE_RX_SERDES_LAST)
        rx_fabric_port = T.fabric_port(self, self.device, rx_fabric_mac_port)
        rx_fabric_mac_port.hld_obj.activate()

        tx_fabric_ports = []
        for lc in OUT_LC_SPECS:
            for port in lc['ports']:
                tx_fabric_ports.append(
                    T.fabric_port(self, self.device,
                                  T.fabric_mac_port(self, self.device, port['slice'], port['ifg'], port['pif'], port['pif'] + 1)
                                  ))

        i = 0
        for lc in OUT_LC_SPECS:
            for port in lc['ports']:
                tx_fabric_ports[i].hld_obj.set_reachable_lc_devices([lc['dev_id']])
                i += 1

        # TODO: Remove this when SDK eliminates the need to poll frm_db_fabric_routing_table
        # when manually setting reachable LC devices.
        # Trigger a poll of frm_db_fabric_routing_table table to update fe_broadcast_bmp table
        self.device.set_bool_property(sdk.la_device_property_e_LC_ADVERTISE_DEVICE_ON_FABRIC_MODE, True)
        # Set flag back to false
        self.device.set_bool_property(sdk.la_device_property_e_LC_ADVERTISE_DEVICE_ON_FABRIC_MODE, False)

        for port in tx_fabric_ports:
            port.hld_obj.get_mac_port().activate()

    def add_mc_group(self, mc_group_id, device_ids):
        self.mc_groups[mc_group_id] = self.device.create_fabric_multicast_group(mc_group_id, sdk.la_replication_paradigm_e_EGRESS)

        devices = [lc['dev_id'] for lc in OUT_LC_SPECS if lc['dev_id'] in device_ids]
        self.mc_groups[mc_group_id].set_devices(devices)
        return self.mc_groups[mc_group_id]

    def create_packets(self, mc_group_id):
        self.fe_mc_pkt = \
            TS_PLB(header_type="ONE_PKT_TS3",       # Single packet, 3 timestamps
                   fcn=0,                           # Forward congestion notification
                   link_fc=0,                       # Link FC
                   plb_context="MC",                # Multicast
                   ts3=[0, 0, 0],                   # Inject fabric time
                   src_device=INGRESS_DEVICE_ID,
                   src_slice=INGRESS_RX_SLICE,
                   reserved=0) / \
            TM(header_type="MMM",               # All Multicast (ingress/fabric/egress)
               vce=0,                           # VOQ congestion experienced flag
               tc=0,                            # Traffic class
               dp=0,                            # DP?
               multicast_id=mc_group_id) / \
            NPU_Header_ext(base_type="NPU_NO_IVE",          # NPU Header data is taken from the actual packet produced
                           fwd_header_type="ETHERNET",      # by LC NSIM in the distributed L2 flooding test.
                           fwd_qos_tag=0x40,                # All values below were not analized for semantic meaning,
                           lb_key=0xc8ef,
                           # they are just pasted from a decoded packet. Except for punt_mc_expand_encap which is passed in.
                           slp_qos_id=15,
                           encap_type=8,
                           punt_mc_expand_encap=mc_group_id,
                           encap=0xa019000000000000,
                           ipv4_first_fragment=1,
                           fwd_slp_info=0x8000a,
                           fwd_relay_id=100) / \
            Ether() / IP()

    @unittest.skipIf(decor.is_hw_device(), "FE tests don't work on hardware.")
    @unittest.skipIf(decor.is_asic5(), "Test is not yet enabled on AR")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route(self):
        """
        Test multicast in the fabric element, the multicast type is not relevant as all types are processed the same.
        """
        MC_GROUP_ID = 13
        self.add_mc_group(MC_GROUP_ID, [10, 20])
        self.create_packets(MC_GROUP_ID)

        ingress_packet = {'data': self.fe_mc_pkt, 'slice': FE_RX_SLICE, 'ifg': FE_RX_IFG, 'pif': FE_RX_SERDES_FIRST}

        expected_packets = [{'data': self.fe_mc_pkt, 'ports': lc['ports']} for lc in OUT_LC_SPECS]

        run_and_compare_list(self, self.device, ingress_packet, expected_packets, TS_PLB, is_fe_multicast=True)

    @unittest.skipIf(decor.is_hw_device(), "FE tests don't work on hardware.")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_route_max_mcid(self):
        """
        Test multicast in the fabric element, ensure you cannot configure the
        reserved drop destination 0xffff
        """
        MC_GROUP_ID = 0xFFFF
        with self.assertRaises(sdk.InvalException):
            self.device.create_fabric_multicast_group(MC_GROUP_ID, sdk.la_replication_paradigm_e_EGRESS)

    @unittest.skipIf(decor.is_hw_device(), "FE tests don't work on hardware.")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_scale_route(self):
        """
        Test multicast in the fabric element, with multicast scale configured and a large SMCID used.
        """
        MC_GROUP_ID = 85001  # test a large value MCID
        self.device.set_int_property(sdk.la_device_property_e_MULTICAST_MCID_SCALE_THRESHOLD, MC_TEST_THRESHOLD)
        self.create_packets(MC_GROUP_ID)
        self.add_mc_group(MC_GROUP_ID, [10, 20])

        # ensure the get API works
        self.device.get_fabric_multicast_group(MC_GROUP_ID)

        ingress_packet = {'data': self.fe_mc_pkt, 'slice': FE_RX_SLICE, 'ifg': FE_RX_IFG, 'pif': FE_RX_SERDES_FIRST}

        expected_packets = [{'data': self.fe_mc_pkt, 'ports': lc['ports']} for lc in OUT_LC_SPECS]

        run_and_compare_list(self, self.device, ingress_packet, expected_packets, TS_PLB, is_fe_multicast=True)

    @unittest.skipIf(decor.is_gibraltar(), "Test is not yet enabled on GB")
    @unittest.skipIf(decor.is_asic4(), "Test is not yet enabled on PL")
    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_scale_route_rpfo(self):
        """
        Test multicast in the fabric element with RPFO. After RPFO the multicast groups will be re-programmed with the same device IDs. This test ensures the same local MCIDs are used after RPFO.
        """
        mc_test_groups = [
            # The following multicast groups should get a unique local MCID as
            # they have different sets of devices.
            {'mc_group_id': 5000,
             'device_ids': [10, 20],
             'local_mcid': 0,
             'mc_group': None, },
            {'mc_group_id': 10000,
             'device_ids': [10],
             'local_mcid': 0,
             'mc_group': None, },
            {'mc_group_id': 50000,
             'device_ids': [20],
             'local_mcid': 0,
             'mc_group': None, },
            # The following multicast groups should reuse the local MCID from
            # above as they have the same set of devices.
            {'mc_group_id': 75000,
             'device_ids': [10, 20],
             'local_mcid': 0,
             'mc_group': None, },
            {'mc_group_id': 100000,
             'device_ids': [10],
             'local_mcid': 0,
             'mc_group': None, },
            {'mc_group_id': 120000,
             'device_ids': [20],
             'local_mcid': 0,
             'mc_group': None, }
        ]

        self.device.set_int_property(sdk.la_device_property_e_MULTICAST_MCID_SCALE_THRESHOLD, MC_TEST_THRESHOLD)

        # for all the test groups setup and save the local MCIDs
        for tg in mc_test_groups:
            tg['mc_group'] = self.add_mc_group(tg['mc_group_id'], tg['device_ids'])
            tg['local_mcid'] = tg['mc_group'].imp().get_local_mcid()

        # do the RP failover
        self.device.crit_fd, self.device.norm_fd = self.device.open_notification_fds(sdk.LA_NOTIFICATION_MASK_ALL)

        if decor.is_hw_device():
            self.rpfo(self.device, [], [])

            # wait for the mac-port state machine to kick in and restore the device links
            time.sleep(5)

            # re-add the multicast groups, assert that they use the same local MCIDs
            # Note: the order is reversed as it should be order independant
            for tg in reversed(mc_test_groups):
                after_mc_group = self.add_mc_group(tg['mc_group_id'], tg['device_ids'])
                self.assertEqual(tg['local_mcid'], after_mc_group.imp().get_local_mcid())


if __name__ == '__main__':
    unittest.main()
