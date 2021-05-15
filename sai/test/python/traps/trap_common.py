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

import pytest
from saicli import *
from sai_test_utils import *
import sai_packet_utils as U


class test_trap_common():

    def create_traps_with_group(self, group):
        policer_id = pytest.tb.get_object_attr(group, SAI_HOSTIF_TRAP_GROUP_ATTR_POLICER)

        args = {}
        args[SAI_POLICER_ATTR_METER_TYPE] = SAI_METER_TYPE_PACKETS
        args[SAI_POLICER_ATTR_MODE] = SAI_POLICER_MODE_SR_TCM
        args[SAI_POLICER_ATTR_CBS] = 2000
        args[SAI_POLICER_ATTR_CIR] = 10000
        args[SAI_POLICER_ATTR_PBS] = 2000
        args[SAI_POLICER_ATTR_PIR] = 10000
        new_policer_id = pytest.tb.create_policer(args)
        pytest.tb.set_trap_group_policer(group, new_policer_id)

        if policer_id != 0:
            pytest.tb.remove_object(policer_id)

        self.arp_trap = pytest.tb.create_trap(SAI_HOSTIF_TRAP_TYPE_ARP_REQUEST, SAI_PACKET_ACTION_TRAP, 255, group)
        self.ndp_trap = pytest.tb.create_trap(SAI_HOSTIF_TRAP_TYPE_IPV6_NEIGHBOR_DISCOVERY, SAI_PACKET_ACTION_TRAP, 255, group)
        self.ip2me_trap = pytest.tb.create_trap(SAI_HOSTIF_TRAP_TYPE_IP2ME, SAI_PACKET_ACTION_TRAP, 0, group)
        self.lldp_trap = pytest.tb.create_trap(SAI_HOSTIF_TRAP_TYPE_LLDP, SAI_PACKET_ACTION_TRAP, 241, group)
        self.dhcp_trap = pytest.tb.create_trap(SAI_HOSTIF_TRAP_TYPE_DHCP, SAI_PACKET_ACTION_TRAP, 242, group)
        self.dhcp6_trap = pytest.tb.create_trap(SAI_HOSTIF_TRAP_TYPE_DHCPV6, SAI_PACKET_ACTION_TRAP, 243, group)
        self.ttlerr_trap = pytest.tb.create_trap(SAI_HOSTIF_TRAP_TYPE_TTL_ERROR, SAI_PACKET_ACTION_TRAP, 244, group)
        self.lacp_trap = pytest.tb.create_trap(SAI_HOSTIF_TRAP_TYPE_LACP, SAI_PACKET_ACTION_TRAP, 255, group)
        self.mtuerr_trap = pytest.tb.create_trap(SAI_HOSTIF_TRAP_TYPE_L3_MTU_ERROR, SAI_PACKET_ACTION_TRAP, 245, group)

    def remove_traps(self):
        pytest.tb.remove_trap(self.arp_trap)
        pytest.tb.remove_trap(self.ndp_trap)
        pytest.tb.remove_trap(self.ip2me_trap)
        pytest.tb.remove_trap(self.lldp_trap)
        pytest.tb.remove_trap(self.dhcp_trap)
        pytest.tb.remove_trap(self.dhcp6_trap)
        pytest.tb.remove_trap(self.ttlerr_trap)
        pytest.tb.remove_trap(self.lacp_trap)
        pytest.tb.remove_trap(self.mtuerr_trap)
