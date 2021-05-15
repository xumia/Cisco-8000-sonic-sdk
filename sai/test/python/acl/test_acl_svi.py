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
from scapy.all import *
import sai_topology as topology
import sai_test_utils as st_utils


@pytest.mark.usefixtures("svi_route_no_tag_v4_topology")
class Test_acl_svi():

    def ingress_acl_table_group_svi_test(self, switch_acl_binding=False):
        # Creating Table Group...
        args = {}
        args[SAI_ACL_TABLE_GROUP_ATTR_ACL_STAGE] = SAI_ACL_STAGE_INGRESS
        acl_table_group = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE_GROUP, args)

        # Creating IPv4 Table...
        args = pytest.tb.generate_ipv4_acl_key()
        table_size = 10
        args[SAI_ACL_TABLE_ATTR_ACL_STAGE] = SAI_ACL_STAGE_INGRESS
        args[SAI_ACL_TABLE_ATTR_SIZE] = table_size
        if switch_acl_binding:
            args[SAI_ACL_TABLE_ATTR_ACL_BIND_POINT_TYPE_LIST] = [SAI_ACL_BIND_POINT_TYPE_SWITCH]
        else:
            args[SAI_ACL_TABLE_ATTR_ACL_BIND_POINT_TYPE_LIST] = [SAI_ACL_BIND_POINT_TYPE_PORT, SAI_ACL_BIND_POINT_TYPE_VLAN]
        acl_table = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE, args)

        # Creating first group member...
        member_count = 0
        args = {}
        args[SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_GROUP_ID] = acl_table_group
        args[SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_ID] = acl_table
        args[SAI_ACL_TABLE_GROUP_MEMBER_ATTR_PRIORITY] = 0
        acl_table_group_member = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE_GROUP_MEMBER, args)
        member_count += 1

        # TODO With RTF ACL currently its not possible to create a new ACL table after an ACL table is already
        # created. Once the capability is available, we can enable back following code.
        """
        # Creating IPv6 Table...
        args = pytest.tb.generate_ipv6_acl_key()
        table_size = 10
        args[SAI_ACL_TABLE_ATTR_ACL_STAGE] = SAI_ACL_STAGE_INGRESS
        args[SAI_ACL_TABLE_ATTR_SIZE] = table_size
        acl_table2 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE, args)

        # Creating second group member...
        args = {}
        args[SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_GROUP_ID] = acl_table_group
        args[SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_ID] = acl_table2
        args[SAI_ACL_TABLE_GROUP_MEMBER_ATTR_PRIORITY] = 0
        acl_table_group_member2 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE_GROUP_MEMBER, args)
        member_count += 1
        """

        if switch_acl_binding:
            pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_INGRESS_ACL, acl_table_group)
        else:
            pytest.tb.bind_acl_to_rif(pytest.tb.svi_rif_id, SAI_ROUTER_INTERFACE_ATTR_INGRESS_ACL, acl_table_group)
            assert pytest.tb.get_rif_ingress_acl(pytest.tb.svi_rif_id) == acl_table_group

        if switch_acl_binding:
            pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_INGRESS_ACL, 0)
        else:
            pytest.tb.bind_acl_to_rif(pytest.tb.svi_rif_id, SAI_ROUTER_INTERFACE_ATTR_INGRESS_ACL, 0)
            pytest.tb.do_warm_boot()
            assert pytest.tb.get_port_ingress_acl(pytest.top.in_port) == 0
            assert pytest.tb.get_rif_ingress_acl(pytest.tb.svi_rif_id) == 0

        entries = sai_object_list_t([])
        arg = sai_attribute_t(SAI_ACL_TABLE_GROUP_ATTR_MEMBER_LIST, entries)
        with st_utils.expect_sai_error(SAI_STATUS_BUFFER_OVERFLOW):
            pytest.tb.apis[SAI_API_ACL].get_acl_table_group_attribute(acl_table_group, 1, arg)

        assert (arg.value.objlist.count == member_count)

        assert len(pytest.tb.get_object_attr(acl_table_group, SAI_ACL_TABLE_GROUP_ATTR_MEMBER_LIST)) == member_count

        # cleanup
        pytest.tb.remove_object(acl_table_group_member)

        # TODO With RTF ACL currently its not possible to create a new ACL table after an ACL table is already
        # created. Once the capability is available, we can enable back following code.
        """
        pytest.tb.remove_object(acl_table_group_member2)
        """
        pytest.tb.remove_object(acl_table_group)
        # TODO With RTF ACL currently its not possible to create a new ACL table after an ACL table is already
        # created. Once the capability is available, we can enable back following code.
        """
        pytest.tb.remove_object(acl_table2)
        """
        pytest.tb.remove_object(acl_table)

    def test_ingress_acl_table_group_svi(self):
        self.ingress_acl_table_group_svi_test()

    def test_ingress_acl_table_group_svi_switch_binding(self):
        self.ingress_acl_table_group_svi_test(switch_acl_binding=True)

    def egress_acl_table_group_svi_test(self, switch_acl_binding=False):
        # Creating Table Group...
        args = {}
        args[SAI_ACL_TABLE_GROUP_ATTR_ACL_STAGE] = SAI_ACL_STAGE_EGRESS
        acl_table_group = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE_GROUP, args)

        # Creating IPv4 Table...
        args = pytest.tb.generate_ipv4_acl_key()
        table_size = 10
        args[SAI_ACL_TABLE_ATTR_ACL_STAGE] = SAI_ACL_STAGE_EGRESS
        args[SAI_ACL_TABLE_ATTR_SIZE] = table_size
        acl_table = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE, args)

        # Creating first group member...
        member_count = 0
        args = {}
        args[SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_GROUP_ID] = acl_table_group
        args[SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_ID] = acl_table
        args[SAI_ACL_TABLE_GROUP_MEMBER_ATTR_PRIORITY] = 0
        acl_table_group_member = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE_GROUP_MEMBER, args)
        member_count += 1

        # TODO With RTF ACL currently its not possible to create a new ACL table after an ACL table is already
        # created. Once the capability is available, we can enable back following code.
        """
        # Creating IPv6 Table...
        args = pytest.tb.generate_ipv6_acl_key()
        table_size = 10
        args[SAI_ACL_TABLE_ATTR_ACL_STAGE] = SAI_ACL_STAGE_EGRESS
        args[SAI_ACL_TABLE_ATTR_SIZE] = table_size
        acl_table2 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE, args)

        # Creating second group member...
        args = {}
        args[SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_GROUP_ID] = acl_table_group
        args[SAI_ACL_TABLE_GROUP_MEMBER_ATTR_ACL_TABLE_ID] = acl_table2
        args[SAI_ACL_TABLE_GROUP_MEMBER_ATTR_PRIORITY] = 0
        acl_table_group_member2 = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_TABLE_GROUP_MEMBER, args)
        member_count += 1
        """

        if switch_acl_binding:
            pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_EGRESS_ACL, acl_table_group)
        else:
            pytest.tb.bind_acl_to_rif(pytest.tb.svi_rif_id, SAI_ROUTER_INTERFACE_ATTR_EGRESS_ACL, acl_table_group)
            pytest.tb.do_warm_boot()
            assert pytest.tb.get_rif_egress_acl(pytest.tb.svi_rif_id) == acl_table_group

        if switch_acl_binding:
            pytest.tb.bind_acl_to_switch(SAI_SWITCH_ATTR_EGRESS_ACL, 0)
        else:
            pytest.tb.bind_acl_to_rif(pytest.tb.svi_rif_id, SAI_ROUTER_INTERFACE_ATTR_EGRESS_ACL, 0)
            assert pytest.tb.get_port_egress_acl(pytest.top.in_port) == 0
            assert pytest.tb.get_rif_egress_acl(pytest.tb.svi_rif_id) == 0

        assert len(pytest.tb.get_object_attr(acl_table_group, SAI_ACL_TABLE_GROUP_ATTR_MEMBER_LIST)) == member_count

        # cleanup
        pytest.tb.remove_object(acl_table_group_member)
        # TODO With RTF ACL currently its not possible to create a new ACL table after an ACL table is already
        # created. Once the capability is available, we can enable back following code.
        """
        pytest.tb.remove_object(acl_table_group_member2)
        """
        pytest.tb.remove_object(acl_table_group)
        # TODO With RTF ACL currently its not possible to create a new ACL table after an ACL table is already
        # created. Once the capability is available, we can enable back following code.
        """
        pytest.tb.remove_object(acl_table2)
        """
        pytest.tb.remove_object(acl_table)

    def test_egress_acl_table_group_svi(self):
        self.egress_acl_table_group_svi_test()

    def test_egress_acl_table_group_svi_with_switch_binding(self):
        self.egress_acl_table_group_svi_test(switch_acl_binding=True)
