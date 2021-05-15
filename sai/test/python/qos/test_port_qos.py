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
from saicli import *
import sai_test_utils as st_utils


@pytest.mark.usefixtures("basic_route_v4_one_port_topology")
class TestPortQosConfig():
    def test_port_to_switch_qos_disabled(self):
        # TODO: Implement port QOS maps
        port_oid = pytest.tb.ports[pytest.top.in_port]

        assert pytest.tb.get_object_attr(port_oid, SAI_PORT_ATTR_QOS_DSCP_TO_TC_MAP) == SAI_NULL_OBJECT_ID
        with st_utils.expect_sai_error(SAI_STATUS_NOT_IMPLEMENTED):
            pytest.tb.set_object_attr(port_oid, SAI_PORT_ATTR_QOS_DSCP_TO_TC_MAP, SAI_NULL_OBJECT_ID)

        assert pytest.tb.get_object_attr(port_oid, SAI_PORT_ATTR_QOS_TC_TO_QUEUE_MAP) == SAI_NULL_OBJECT_ID
        with st_utils.expect_sai_error(SAI_STATUS_NOT_IMPLEMENTED):
            pytest.tb.set_object_attr(port_oid, SAI_PORT_ATTR_QOS_TC_TO_QUEUE_MAP, SAI_NULL_OBJECT_ID)
