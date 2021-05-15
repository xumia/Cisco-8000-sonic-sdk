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
import sai_test_utils as st_utils


@pytest.mark.usefixtures("dot1q_bridge_v4_topology")
class Test_attributes():

    def test_topology_config(self):
        pytest.top.deconfigure_dot1q_bridge_topology()
        pytest.top.configure_dot1q_bridge_topology()
        pytest.top.deconfigure_dot1q_bridge_topology()
        pytest.top.configure_dot1q_bridge_topology()

    def check_vlan_members(self, num, vlan_id):
        oblst = S.sai_object_list_t([0, 0, 0, 0])
        attr = S.sai_attribute_t(S.SAI_VLAN_ATTR_MEMBER_LIST, oblst)
        pytest.tb.apis[S.SAI_API_VLAN].get_vlan_attribute(pytest.tb.vlans[vlan_id], 1, attr)
        self.vlan_members = attr.value.objlist.to_pylist()
        assert len(self.vlan_members) == num

    def test_vlan_member_attributes(self):
        # check for buffer overflow condition with nullptr list
        oblst = S.sai_object_list_t([])
        attr = S.sai_attribute_t(S.SAI_VLAN_ATTR_MEMBER_LIST, oblst)
        with st_utils.expect_sai_error(S.SAI_STATUS_BUFFER_OVERFLOW):
            pytest.tb.apis[S.SAI_API_VLAN].get_vlan_attribute(pytest.tb.vlans[pytest.top.vlan], 1, attr)
        assert(attr.value.objlist.count == 2)

        pytest.tb.configure_vlans([501])
        self.check_vlan_members(0, 501)
        new_vlan_members = pytest.tb.configure_vlan_members(
            [{"vlan": 501, "port": pytest.top.out_port, "is_tag": True}])
        self.check_vlan_members(1, 501)
        for v_member in new_vlan_members:
            pytest.tb.remove_vlan_member(v_member)

    def test_vlan_attributes(self):
        self.check_vlan_members(2, pytest.top.vlan)

        attr = S.sai_attribute_t(S.SAI_VLAN_MEMBER_ATTR_VLAN_ID, 0)
        pytest.tb.apis[S.SAI_API_VLAN].get_vlan_member_attribute(self.vlan_members[0], 1, attr)
        # vlan member attr return vlan obj
        attr1 = S.sai_attribute_t(S.SAI_VLAN_ATTR_VLAN_ID, 0)
        pytest.tb.apis[S.SAI_API_VLAN].get_vlan_attribute(attr.value.oid, 1, attr1)
        # vlan attr return vlan id
        assert attr1.value.u16 == pytest.top.vlan

        attr2 = S.sai_attribute_t(S.SAI_VLAN_ATTR_BROADCAST_FLOOD_CONTROL_TYPE, S.SAI_VLAN_FLOOD_CONTROL_TYPE_ALL)
        pytest.tb.apis[S.SAI_API_VLAN].get_vlan_attribute(attr.value.oid, 1, attr2)
        assert attr2.value.u8 == S.SAI_VLAN_FLOOD_CONTROL_TYPE_ALL

        pytest.tb.set_object_attr(attr.value.oid,
                                  S.SAI_VLAN_ATTR_BROADCAST_FLOOD_CONTROL_TYPE,
                                  S.SAI_VLAN_FLOOD_CONTROL_TYPE_L2MC_GROUP, True)

        pytest.tb.set_object_attr(attr.value.oid, S.SAI_VLAN_ATTR_BROADCAST_FLOOD_CONTROL_TYPE, S.SAI_VLAN_FLOOD_CONTROL_TYPE_ALL)

    def test_switch_defaults(self):
        attr = S.sai_attribute_t(S.SAI_SWITCH_ATTR_DEFAULT_1Q_BRIDGE_ID, 0)
        pytest.tb.apis[S.SAI_API_SWITCH].get_switch_attribute(pytest.tb.switch_id, 1, attr)
        assert S.sai_object_type_query(attr.value.oid) == S.SAI_OBJECT_TYPE_BRIDGE
        self.default_1q_bridge = attr.value.oid

        # check port list overflow condition
        oblst = S.sai_object_list_t([])
        attr_plist = S.sai_attribute_t(S.SAI_BRIDGE_ATTR_PORT_LIST, oblst)
        with st_utils.expect_sai_error(S.SAI_STATUS_BUFFER_OVERFLOW):
            pytest.tb.apis[S.SAI_API_BRIDGE].get_bridge_attribute(self.default_1q_bridge, 1, attr_plist)
        if (attr_plist.value.objlist.count == 0):
            raise

        oblst = S.sai_object_list_t([0, 0, 0, 0])
        attr_plist = S.sai_attribute_t(S.SAI_BRIDGE_ATTR_PORT_LIST, oblst)
        pytest.tb.apis[S.SAI_API_BRIDGE].get_bridge_attribute(self.default_1q_bridge, 1, attr_plist)
        self.bports_1q = attr_plist.value.objlist.to_pylist()
        assert len(self.bports_1q) == 2

        attr_v = S.sai_attribute_t(S.SAI_SWITCH_ATTR_DEFAULT_VLAN_ID, 0)
        pytest.tb.apis[S.SAI_API_SWITCH].get_switch_attribute(pytest.tb.switch_id, 1, attr_v)
        assert S.sai_object_type_query(attr_v.value.oid) == S.SAI_OBJECT_TYPE_VLAN
        assert attr.value.oid & 0xFFFFF == attr_v.value.oid & 0xFFFFF
