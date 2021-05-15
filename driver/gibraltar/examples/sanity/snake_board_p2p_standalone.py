#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

###
# Implement of L2 P2P snake test
###

from leaba import sdk

import network_objects
from sanity_constants import *


class snake_board_p2p_topology:
    BASE_VID1 = 0x800
    AC_PORT_BASE_GID = 0x10

    def __init__(self, la_dev):
        self.la_dev = la_dev
        self.reset()

    def reset(self):
        self.tx_ac_ports = []
        self.rx_ac_ports = []

    def initialize(self, base_topology):
        ac_port_gid = snake_board_p2p_topology.AC_PORT_BASE_GID

        # Create the Tx ports
        for eth_port_index in range(base_topology.mac_ports_num):

            (status, ac_port) = self.la_dev.create_ac_l2_service_port(ac_port_gid,
                                                                      base_topology.eth_ports[eth_port_index],
                                                                      1,  # vid1
                                                                      0,  # vid2
                                                                      network_objects.ingress_qos_profile_def.hld_obj,
                                                                      network_objects.egress_qos_profile_def.hld_obj)
            if (status != sdk.LA_STATUS_SUCCESS) or (ac_port is None):
                raise Exception('Error: create_ac_l2_service_port failed. status=%d eth_port_index=%d' % (status, eth_port_index))

            status = ac_port.set_stp_state(sdk.la_port_stp_state_e_FORWARDING)
            if status != sdk.LA_STATUS_SUCCESS:
                raise Exception('Error: set_stp_state failed. status=%d eth_port_index=%d' % (status, eth_port_index))

            ac_port_gid += 1

            # Set the VLAN tag
            eve = sdk.la_vlan_edit_command()
            eve.num_tags_to_push = 1
            eve.num_tags_to_pop = 1
            eve.tag0.tpid = TPID_Dot1Q
            eve.tag0.tci.fields.vid = snake_board_p2p_topology.BASE_VID1 + ((eth_port_index + 1) % base_topology.mac_ports_num)
            status = ac_port.set_egress_vlan_edit_command(eve)
            if status != sdk.LA_STATUS_SUCCESS:
                raise Exception(
                    'Error: set_egress_vlan_edit_command failed. status=%d eth_port_index=%d' %
                    (status, eth_port_index))

            # Store all objects that need to be destroyed later
            self.tx_ac_ports.append(ac_port)

        # Create the Rx ports
        for eth_port_index in range(base_topology.mac_ports_num):
            for vid_index in range(base_topology.mac_ports_num):
                (status, ac_port) = self.la_dev.create_ac_l2_service_port(ac_port_gid,
                                                                          base_topology.eth_ports[eth_port_index],
                                                                          snake_board_p2p_topology.BASE_VID1 + vid_index,  # vid1
                                                                          0,  # vid2
                                                                          network_objects.ingress_qos_profile_def.hld_obj,
                                                                          network_objects.egress_qos_profile_def.hld_obj)
                if (status != sdk.LA_STATUS_SUCCESS) or (ac_port is None):
                    raise Exception(
                        'Error: create_ac_l2_service_port failed. status=%d eth_port_index=%d vid_index=%d' %
                        (status, eth_port_index, vid_index))

                status = ac_port.set_stp_state(sdk.la_port_stp_state_e_FORWARDING)
                if status != sdk.LA_STATUS_SUCCESS:
                    raise Exception(
                        'Error: set_stp_state failed. status=%d eth_port_index=%d vid_index=%d' %
                        (status, eth_port_index, vid_index))

                ac_port_gid += 1

                # Set P2P connection
                status = ac_port.set_destination(self.tx_ac_ports[vid_index])
                if status != sdk.LA_STATUS_SUCCESS:
                    raise Exception(
                        'Error: set_destination failed. status=%d eth_port_index=%d vid_index=%d' %
                        (status, eth_port_index, vid_index))

                # Store all objects that need to be destroyed later
                self.rx_ac_ports.append(ac_port)

        self.la_dev.flush()

    def teardown(self):
        for ac_port in self.rx_ac_ports:
            status = self.la_dev.destroy(ac_port)
            if status != sdk.LA_STATUS_SUCCESS:
                raise Exception('destroy failed. status=%d' % status)
        for ac_port in self.tx_ac_ports:
            status = self.la_dev.destroy(ac_port)
            if status != sdk.LA_STATUS_SUCCESS:
                raise Exception('destroy failed. status=%d' % status)

        self.la_dev.flush()
        self.reset()
