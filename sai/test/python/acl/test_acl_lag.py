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
from saicli import *
import sai_packet_utils as U
import sai_test_base as st_base
import sai_test_utils as st_utils
from scapy.all import *
import sai_topology as topology
import time


@pytest.mark.skipif(st_utils.is_sai_15x(), reason="Disabled on SAI 1.5.x")
@pytest.mark.usefixtures("dot1q_bridge_v4_lag_topology")
class Test_acl_lag():

    def acl_configure(self):

        # Creating Table Group...
        args = {}
        args[SAI_ACL_TABLE_GROUP_ATTR_ACL_STAGE] = SAI_ACL_STAGE_EGRESS
        self.acl_table_group = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE_GROUP, args)

        # Creating IPv4 Table...
        args = pytest.tb.generate_ipv4_acl_key()
        table_size = 10
        args[SAI_ACL_TABLE_ATTR_ACL_STAGE] = SAI_ACL_STAGE_EGRESS
        args[SAI_ACL_TABLE_ATTR_SIZE] = table_size
        self.acl_table = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE, args)

        # Creating first group member...
        args = {}
        args[SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_GROUP_ID] = self.acl_table_group
        args[SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_ID] = self.acl_table
        args[SAI_ACL_TABLE_GROUP_MEMBER_ATTR_PRIORITY] = 0
        self.acl_table_group_member = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE_GROUP_MEMBER, args)

        # TODO With RTF ACL currently its not possible to create a new ACL table after an ACL table is already
        # created. Once the capability is available, we can enable back following code.
        """
        # Creating IPv6 Table...
        args = pytest.tb.generate_ipv6_acl_key()
        table_size = 10
        args[SAI_ACL_TABLE_ATTR_ACL_STAGE] = SAI_ACL_STAGE_EGRESS
        args[SAI_ACL_TABLE_ATTR_SIZE] = table_size
        acl_table2 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE, args)

        pytest.tb.do_warm_boot()

        # Creating second group member...
        args = {}
        args[SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_GROUP_ID] = acl_table_group
        args[SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_ID] = acl_table2
        args[SAI_ACL_TABLE_GROUP_MEMBER_ATTR_PRIORITY] = 0
        acl_table_group_member2 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE_GROUP_MEMBER, args)
        """

    def acl_deconfigure(self):
        # cleanup
        pytest.tb.remove_object(self.acl_table_group_member)
        # TODO With RTF ACL currently its not possible to create a new ACL table after an ACL table is already
        # created. Once the capability is available, we can enable back following code.
        """
        pytest.tb.remove_object(self.acl_table_group_member2)
        """
        pytest.tb.remove_object(self.acl_table_group)
        # TODO With RTF ACL currently its not possible to create a new ACL table after an ACL table is already
        # created. Once the capability is available, we can enable back following code.
        """
        pytest.tb.remove_object(self.acl_table2)
        """
        pytest.tb.remove_object(self.acl_table)

    def acl_lag_test(self, switch_acl_binding=False):
        self.acl_configure()

        if switch_acl_binding:
            pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_EGRESS_ACL, self.acl_table_group)
        else:
            pytest.tb.bind_acl_to_lag(pytest.top.lag_id1, SAI_LAG_ATTR_EGRESS_ACL, self.acl_table_group)
            assert pytest.tb.get_lag_egress_acl(pytest.top.lag_id1) == self.acl_table_group

        if switch_acl_binding:
            pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_EGRESS_ACL, 0)
        else:
            pytest.tb.bind_acl_to_lag(pytest.top.lag_id1, SAI_LAG_ATTR_EGRESS_ACL, 0)
            assert pytest.tb.get_lag_egress_acl(pytest.top.lag_id1) == 0

        self.acl_deconfigure()

    def test_acl_lag(self):
        self.acl_lag_test()

    def test_acl_lag_with_switch_binding(self):
        self.acl_lag_test(switch_acl_binding=True)

    def test_acl_bridge_port_after_acl_switch_binding(self):
        pytest.top.deconfigure_dot1q_bridge_lag_topology()

        # configure acl and bind to switch
        self.acl_configure()
        pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_EGRESS_ACL, self.acl_table_group)

        pytest.top.configure_dot1q_bridge_lag_topology()

        pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_EGRESS_ACL, 0)
        self.acl_deconfigure()
