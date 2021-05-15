#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
import sai_test_base as st_base
import sai_test_utils as st_utils
import saicli as S

# TODO: Negative testing for create_switch


class Test_switch_attr():
    @pytest.mark.skipif(st_utils.is_sai_15x(), reason="Disabled on SAI 1.5.x")
    def test_defaults(self):
        tb = st_base.sai_test_base()
        tb.setUp()
        assert tb.get_object_attr(tb.switch_id, S.SAI_SWITCH_ATTR_TYPE) == S.SAI_SWITCH_TYPE_NPU
        assert tb.get_object_attr(tb.switch_id, S.SAI_SWITCH_ATTR_ECMP_MEMBERS) == S.LSAI_MAX_ECMP_GROUP_MEMBERS
        tb.tearDown()

    @pytest.mark.skipif(st_utils.is_sai_15x(), reason="Disabled on SAI 1.5.x")
    def test_switch_type(self):
        tb = st_base.sai_test_base()
        tb.setUp(optional_switch_create_time_attrs=[S.sai_attribute_t(S.SAI_SWITCH_ATTR_TYPE, S.SAI_SWITCH_TYPE_NPU)])
        got_attr_switch_type = tb.get_object_attr(tb.switch_id, S.SAI_SWITCH_ATTR_TYPE)
        assert got_attr_switch_type == S.SAI_SWITCH_TYPE_NPU
        tb.tearDown()
