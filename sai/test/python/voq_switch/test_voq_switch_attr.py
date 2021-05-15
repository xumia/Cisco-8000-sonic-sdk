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

import os
import pytest
import sai_test_base as st_base
import saicli as S
import sai_test_utils as st_utils

# TODO: Test SP GID's for all SP's are correct, including internal ports


@pytest.mark.usefixtures("two_sp_topology")
@pytest.mark.skipif(st_utils.is_sai_15x(), reason="Disabled on SAI 1.5.x")
class Test_voq_switch():
    def test_switch_voq_id(self):
        switch_id = pytest.tb.get_object_attr(pytest.tb.switch_id, S.SAI_SWITCH_ATTR_SWITCH_ID)
        assert switch_id is not None
        assert switch_id == st_utils.PortConfig.VOQ_SWITCH_ID

    def test_max_system_cores(self):
        max_system_cores = pytest.tb.get_object_attr(pytest.tb.switch_id, S.SAI_SWITCH_ATTR_MAX_SYSTEM_CORES)
        assert max_system_cores is not None
        assert max_system_cores == pytest.top.port_cfg.max_system_cores

    def test_switch_sysport_list(self):
        # Retrieve system port OIDs using SAI_PORT_ATTR_SYSTEM_PORT attr of each port.
        mac_sp_oids = [pytest.tb.get_object_attr(port_oid, S.SAI_PORT_ATTR_SYSTEM_PORT)
                       for port_oid in pytest.tb.ports.values()]
        assert None not in mac_sp_oids

        # Verify system port list returned from switch attr
        # SAI_SWITCH_ATTR_SYSTEM_PORT_LIST contains mac ones obtained
        # above.
        num_system_ports = pytest.tb.get_object_attr(pytest.tb.switch_id, S.SAI_SWITCH_ATTR_NUMBER_OF_SYSTEM_PORTS)
        assert num_system_ports == len(pytest.top.port_cfg.sysport_cfgs)
        switch_system_ports = pytest.tb.get_object_attr(pytest.tb.switch_id, S.SAI_SWITCH_ATTR_SYSTEM_PORT_LIST)
        assert len(switch_system_ports) == num_system_ports
        for mac_sp in mac_sp_oids:
            assert mac_sp in switch_system_ports
