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
import saicli as S
import sai_test_utils as st_utils

# TODO: Test close-to-max port_id, checking that the leaba min-sp-gid
# addition throws an error when it will wrap.


@pytest.mark.usefixtures("two_sp_topology")
@pytest.mark.skipif(st_utils.is_sai_15x(), reason="Disabled on SAI 1.5.x")
class Test_system_port_attr():
    def test_port_system_port_id(self):
        for global_pif_lane, port_oid in pytest.tb.ports.items():
            sp_oid = pytest.tb.get_object_attr(port_oid, S.SAI_PORT_ATTR_SYSTEM_PORT)
            sp_provided_port_oid = pytest.tb.get_object_attr(sp_oid, S.SAI_SYSTEM_PORT_ATTR_PORT)
            assert port_oid == sp_provided_port_oid

            # Verify SAI_SYSTEM_PORT_ATTR_TYPE
            sp_type = pytest.tb.get_object_attr(sp_oid, S.SAI_SYSTEM_PORT_ATTR_TYPE)
            assert sp_type == S.SAI_SYSTEM_PORT_TYPE_LOCAL

            # Verify SAI_SYSTEM_PORT_ATTR_CONFIG_INFO
            sp_id, switch_id, core_idx, core_port_idx, speed, num_voq = pytest.tb.get_object_attr(
                sp_oid, S.SAI_SYSTEM_PORT_ATTR_CONFIG_INFO)

            slice_ifg_pif = st_utils.lane_to_slice_ifg_pif(global_pif_lane)
            global_ifg_index = (2 * slice_ifg_pif["slice"]) + slice_ifg_pif["ifg"]

            port_speed = pytest.tb.get_object_attr(port_oid, S.SAI_PORT_ATTR_SPEED)
            assert port_speed is not None

            assert switch_id == st_utils.PortConfig.VOQ_SWITCH_ID
            assert core_idx == global_ifg_index
            assert core_port_idx == slice_ifg_pif["pif"]
            assert speed == port_speed
            assert num_voq == 8

    def test_remote_sp_not_implemented(self):
        with st_utils.expect_sai_error(S.SAI_STATUS_INVALID_ATTR_VALUE_0 + S.SAI_SYSTEM_PORT_ATTR_CONFIG_INFO):
            pytest.tb.create_system_port([123, pytest.top.port_cfg.VOQ_SWITCH_ID + 1, 0, 0, 1000, 8])

    def test_bad_ifg(self):
        with st_utils.expect_sai_error(S.SAI_STATUS_INVALID_ATTR_VALUE_0 + S.SAI_SYSTEM_PORT_ATTR_CONFIG_INFO):
            pytest.tb.create_system_port([123, pytest.top.port_cfg.VOQ_SWITCH_ID, 20, 0, 1000, 8])

    def test_duplicate_local_system_port(self):
        # Expect error if trying to create a duplicate local system
        # port. This should try to make another Leaba system port of
        # the same GID, resulting in an "object in use" SAI error
        # after Leaba status translation
        with st_utils.expect_sai_error(S.SAI_STATUS_OBJECT_IN_USE):
            pytest.tb.create_system_port(pytest.top.port_cfg.in_sys_port_cfg)
