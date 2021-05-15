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
import sai_test_base as st_base
import sai_test_utils as st_utils
import saicli as S


@pytest.mark.usefixtures("router_lag_v4_topology")
class Test_lag_attr():
    def test_egress_disable(self):
        pytest.tb.set_lag_mem_egress_set_state(pytest.top.lag_member_id, disable=False)
        pytest.tb.set_lag_mem_egress_set_state(pytest.top.lag_member_id, disable=True)
        pytest.tb.set_lag_mem_egress_set_state(pytest.top.lag_member_id, disable=False)

    def test_ingress_disable(self):
        pytest.tb.set_lag_mem_ingress_set_state(pytest.top.lag_member_id, disable=False)
        pytest.tb.set_lag_mem_ingress_set_state(pytest.top.lag_member_id, disable=True)
        pytest.tb.set_lag_mem_ingress_set_state(pytest.top.lag_member_id, disable=False)
