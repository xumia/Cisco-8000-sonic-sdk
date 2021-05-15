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

import pytest
import saicli as S


@pytest.mark.usefixtures("basic_route_v4_topology")
class Test_hostif_netdev():
    def test_hostif_netdev(self):
        hostif_oid = pytest.tb.create_hostif(
            S.SAI_HOSTIF_TYPE_NETDEV, pytest.tb.ports[pytest.top.in_port], "UTHostIf", verify=[True, False])
        pytest.tb.set_object_attr(hostif_oid, S.SAI_HOSTIF_ATTR_OPER_STATUS, True, verify=True)
        arp_trap = pytest.tb.create_trap(S.SAI_HOSTIF_TRAP_TYPE_ARP_REQUEST, S.SAI_PACKET_ACTION_TRAP, 255)
        hostif_entry_oid = pytest.tb.create_hostif_table_entry(S.SAI_HOSTIF_TABLE_ENTRY_TYPE_PORT,
                                                               pytest.tb.ports[pytest.top.in_port],
                                                               arp_trap,
                                                               S.SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_NETDEV_PHYSICAL_PORT,
                                                               verify=[True,
                                                                       False])
        pytest.tb.remove_object(hostif_entry_oid)
        pytest.tb.remove_object(arp_trap)
        pytest.tb.remove_object(hostif_oid)
