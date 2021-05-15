#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2021-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

import pytest
import sai_test_utils as st_utils
from saicli import *


@pytest.fixture(scope="class")
def pfc_active(base_v4_topology):
    # Ports only start getting RX CGM SQ drop counters once PFC has
    # been at least activated on some port, so create and port,
    # activate PFC, then remove the port
    pytest.tb.configure_ports([pytest.top.port_cfg.in_port_cfg])
    port_oid = pytest.tb.ports[pytest.top.port_cfg.in_port]
    pytest.tb.set_object_attr(port_oid, SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL, 0x1)
    pytest.tb.set_object_attr(port_oid, SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL, 0)
    pytest.tb.remove_port(pytest.top.port_cfg.in_port)


@pytest.mark.usefixtures("pfc_active")
class Test_pfc_drop():
    '''
    Testing the allocation of 64 drop counters with 8 counters per
    slice during various port creation. Not currently sending
    traffic and verifying the drop counter increments. Instead,
    using the Python la_device object to access which drop counter
    offset was was set during the TC RX CGM SQ mapping call.
    '''

    def get_tc_drop_offset(self, pif, tc):
        dev = pytest.tb.la_device
        sip = st_utils.lane_to_slice_ifg_pif(pif)
        mac_port = dev.get_mac_port(sip["slice"], sip["ifg"], sip["pif"])
        sq_profile, group_index, drop_offset = mac_port.get_tc_rx_cgm_sq_mapping(tc)
        return drop_offset

    def verify_drop_offset_on_slice(self, slice_id):
        # Create 10 ports on the same slice ignoring PFC, and observe
        # that their default RX CGM SQ mapping defaults to 0 after the
        # 7th port is created.
        #
        # NOTE: Leaves the ports created to test multiple slices
        # having separate counter allocation. These ports should be
        # removed before the end of a test.
        serdes_lanes = 1
        lane_speed = 25
        starting_pif = (2 * slice_id) << 8
        pifs = range(starting_pif, starting_pif + 10)
        for i, pif in enumerate(pifs):
            # Create port
            port_oid = pytest.tb.create_port(st_utils.port_config(pif, serdes_lanes, lane_speed))
            for tc in range(8):
                drop_offset = self.get_tc_drop_offset(pif, tc)
                if i < 7:
                    assert drop_offset == i + 1
                else:
                    assert drop_offset == 0

    def test_drop_offset_all_slices(self):
        # Verify all slices have their own drop offsets
        for slice_id in range(pytest.top.port_cfg.slices_per_dev):
            self.verify_drop_offset_on_slice(slice_id)

        # Get all new port OIDs and remove them
        num_ports, swig_port_oids = pytest.tb.get_object_keys(SAI_OBJECT_TYPE_PORT)
        port_oids = []
        for i in range(num_ports):
            pytest.tb.remove_object(swig_port_oids[i])

    def test_drop_offset_counter_freeing(self):
        serdes_lanes = 1
        lane_speed = 25

        # Create 2 ports
        pif = 0x400
        port_oid = pytest.tb.create_port(st_utils.port_config(pif, serdes_lanes, lane_speed))
        for tc in range(8):
            assert self.get_tc_drop_offset(pif, tc) == 1
        pif2 = 0x401
        port_oid2 = pytest.tb.create_port(st_utils.port_config(pif2, serdes_lanes, lane_speed))
        for tc in range(8):
            assert self.get_tc_drop_offset(pif2, tc) == 2

        # Remove first port
        pytest.tb.remove_object(port_oid)

        # Verify that a new port gets drop offset 1
        pif3 = 0x402
        port_oid3 = pytest.tb.create_port(st_utils.port_config(pif3, serdes_lanes, lane_speed))
        for tc in range(8):
            assert self.get_tc_drop_offset(pif3, tc) == 1

        # And another port gets drop offset 3
        pif4 = 0x403
        port_oid4 = pytest.tb.create_port(st_utils.port_config(pif4, serdes_lanes, lane_speed))
        for tc in range(8):
            assert self.get_tc_drop_offset(pif4, tc) == 3

        # Remove all remaining ports
        for oid in [port_oid2, port_oid3, port_oid4]:
            pytest.tb.remove_object(oid)

    def test_drop_offset_over_allocation_freeing(self):
        # Create 9 ports, thus making the 8th and 9th overlap on drop
        # offset 0.
        serdes_lanes = 1
        lane_speed = 25
        starting_pif = 0x200
        pifs = range(starting_pif, starting_pif + 9)
        port_oids = []
        for i, pif in enumerate(pifs):
            # Create port
            port_oid = pytest.tb.create_port(st_utils.port_config(pif, serdes_lanes, lane_speed))
            port_oids.append(port_oid)
            for tc in range(8):
                drop_offset = self.get_tc_drop_offset(pif, tc)
                if i < 7:
                    assert drop_offset == i + 1
                else:
                    assert drop_offset == 0

        # Remove the last 3 ports, which should only free up offset 7 and not 0
        for port_oid in port_oids[-3:]:
            pytest.tb.remove_object(port_oid)
        port_oids = port_oids[:-3]

        # Verify that a new port gets offset 7 and not 0
        new_pif = starting_pif + 10
        port_oids.append(pytest.tb.create_port(st_utils.port_config(new_pif, serdes_lanes, lane_speed)))
        for tc in range(8):
            assert self.get_tc_drop_offset(new_pif, tc) == 7

        # Clean up
        for port_oid in port_oids:
            pytest.tb.remove_object(port_oid)
