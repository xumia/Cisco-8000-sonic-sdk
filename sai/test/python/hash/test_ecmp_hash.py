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
from sai_test_utils import *
import sai_test_utils as st_utils


@pytest.mark.usefixtures("base_v4_topology")
class Test_sai_hash():
    def test_ecmp(self):
        # Get and try to remove default profile
        obj_num, obj_list = pytest.tb.get_object_keys(SAI_OBJECT_TYPE_HASH)
        assert(obj_num == 1)
        default_hash_obj_id = obj_list[0]
        obj_num1, obj_list1 = pytest.tb.get_object_keys(SAI_OBJECT_TYPE_HASH)
        new_hash_obj_id = obj_list[0]
        assert(default_hash_obj_id == new_hash_obj_id)

        # Should not be able to remove default profile
        with expect_sai_error(SAI_STATUS_NOT_IMPLEMENTED):
            pytest.tb.remove_object(default_hash_obj_id)

        hash_attr = [[SAI_HASH_ATTR_NATIVE_HASH_FIELD_LIST, [SAI_NATIVE_HASH_FIELD_VLAN_ID]]]

        with expect_sai_error(SAI_STATUS_NOT_IMPLEMENTED):
            pytest.tb.create_object(SAI_OBJECT_TYPE_HASH, hash_attr)

        with expect_sai_error(SAI_STATUS_NOT_IMPLEMENTED):
            pytest.tb.set_object_attr(default_hash_obj_id, SAI_HASH_ATTR_NATIVE_HASH_FIELD_LIST, [SAI_NATIVE_HASH_FIELD_VLAN_ID])

        out_list = pytest.tb.get_object_attr(default_hash_obj_id, SAI_HASH_ATTR_NATIVE_HASH_FIELD_LIST)
        assert out_list == [SAI_NATIVE_HASH_FIELD_VLAN_ID,
                            SAI_NATIVE_HASH_FIELD_IP_PROTOCOL,
                            SAI_NATIVE_HASH_FIELD_ETHERTYPE,
                            SAI_NATIVE_HASH_FIELD_L4_SRC_PORT,
                            SAI_NATIVE_HASH_FIELD_L4_DST_PORT,
                            SAI_NATIVE_HASH_FIELD_SRC_MAC,
                            SAI_NATIVE_HASH_FIELD_DST_MAC]

        # check buffer overflow condition
        hash_list = sai_u32_list_t([])
        arg = sai_attribute_t(SAI_HASH_ATTR_NATIVE_HASH_FIELD_LIST, hash_list)
        with st_utils.expect_sai_error(SAI_STATUS_BUFFER_OVERFLOW):
            pytest.tb.apis[SAI_API_HASH].get_hash_attribute(default_hash_obj_id, 1, arg)
        assert (arg.value.objlist.count == len(out_list))
