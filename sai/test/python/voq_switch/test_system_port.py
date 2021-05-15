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

# TODO: Test removing internal system ports, expect error


@pytest.mark.usefixtures("two_sp_topology")
@pytest.mark.skipif(st_utils.is_sai_15x(), reason="Disabled on SAI 1.5.x")
class Test_system_port():
    def test_remove_create_sp(self):
        # Remove in_port's system port
        in_port_oid = pytest.tb.ports[pytest.top.port_cfg.in_port]
        in_sp_oid = pytest.tb.get_object_attr(in_port_oid, S.SAI_PORT_ATTR_SYSTEM_PORT)
        pytest.tb.remove_object(in_sp_oid)

        # Expect failure to retrieve system port for in port
        assert pytest.tb.get_object_attr(in_port_oid, S.SAI_PORT_ATTR_SYSTEM_PORT) is None

        # Get out_port's system port
        out_port_oid = pytest.tb.ports[pytest.top.port_cfg.out_port]
        out_sp_oid = pytest.tb.get_object_attr(out_port_oid, S.SAI_PORT_ATTR_SYSTEM_PORT)
        assert out_sp_oid is not None

        # Recreate in_port's system port
        in_sp_oid = pytest.tb.create_system_port(pytest.top.port_cfg.in_sys_port_cfg)

        # Verify new SP OID matches
        attr_in_sp_oid = pytest.tb.get_object_attr(in_port_oid, S.SAI_PORT_ATTR_SYSTEM_PORT)
        assert attr_in_sp_oid == in_sp_oid

    def test_remove_create_port(self):
        # Remove in_port, expect "object in use" error since system
        # port is still up
        with st_utils.expect_sai_error(S.SAI_STATUS_OBJECT_IN_USE):
            pytest.tb.remove_port(pytest.top.port_cfg.in_port)

    def test_invalid_remove(self):
        in_port_oid = pytest.tb.ports[pytest.top.port_cfg.in_port]
        in_sp_oid = pytest.tb.get_object_attr(in_port_oid, S.SAI_PORT_ATTR_SYSTEM_PORT)

        out_port_oid = pytest.tb.ports[pytest.top.port_cfg.out_port]
        out_sp_oid = pytest.tb.get_object_attr(out_port_oid, S.SAI_PORT_ATTR_SYSTEM_PORT)

        # Picking a guaranteed bad SP OID, but leaving it nearby in
        # the valid range for this type of object
        bad_sp_oid = max(in_sp_oid, out_sp_oid) + 1

        with st_utils.expect_sai_error(S.SAI_STATUS_ITEM_NOT_FOUND):
            pytest.tb.remove_object(bad_sp_oid)

    def test_get_object_keys(self):
        obj_count, sp_oids_swig = pytest.tb.get_object_keys(S.SAI_OBJECT_TYPE_SYSTEM_PORT)
        sp_oids = [sp_oids_swig[i] for i in range(obj_count)]

        num_system_ports = pytest.tb.get_object_attr(pytest.tb.switch_id, S.SAI_SWITCH_ATTR_NUMBER_OF_SYSTEM_PORTS)
        assert num_system_ports == len(pytest.top.port_cfg.sysport_cfgs)
        switch_system_ports = pytest.tb.get_object_attr(pytest.tb.switch_id, S.SAI_SWITCH_ATTR_SYSTEM_PORT_LIST)
        assert len(switch_system_ports) == num_system_ports

        assert obj_count == num_system_ports
        assert set(sp_oids) == set(switch_system_ports)


@pytest.mark.usefixtures("two_port_no_sp_topology")
@pytest.mark.skipif(st_utils.is_sai_15x(), reason="Disabled on SAI 1.5.x")
class Test_system_port_create():
    def test_out_of_range_sp_params(self):
        exceeds_3_bytes = (1 << (3 * 8))
        exceeds_1_byte = (1 << 8)
        sp_bad_core_idx_cfg = [10, pytest.top.port_cfg.VOQ_SWITCH_ID, exceeds_3_bytes, 0, 1000, 8]
        sp_bad_core_port_idx_cfg = [10, pytest.top.port_cfg.VOQ_SWITCH_ID, 0, exceeds_1_byte, 1000, 8]
        with st_utils.expect_sai_error(S.SAI_STATUS_INVALID_ATTR_VALUE_0 + S.SAI_SYSTEM_PORT_ATTR_CONFIG_INFO):
            pytest.tb.create_system_port(sp_bad_core_idx_cfg)

        with st_utils.expect_sai_error(S.SAI_STATUS_INVALID_ATTR_VALUE_0 + S.SAI_SYSTEM_PORT_ATTR_CONFIG_INFO):
            pytest.tb.create_system_port(sp_bad_core_port_idx_cfg)

    def test_invalid_num_voq(self):
        bad_num_voq_cfg = list(pytest.top.port_cfg.in_sys_port_cfg)
        bad_num_voq_cfg[5] = 1
        with st_utils.expect_sai_error(S.SAI_STATUS_INVALID_ATTR_VALUE_0 + S.SAI_SYSTEM_PORT_ATTR_CONFIG_INFO):
            pytest.tb.create_system_port(bad_num_voq_cfg)

    def test_unsupported_sp_admin_state(self):
        with st_utils.expect_sai_error(S.SAI_STATUS_ATTR_NOT_SUPPORTED_0 + S.SAI_SYSTEM_PORT_ATTR_ADMIN_STATE):
            pytest.tb.create_system_port(pytest.top.port_cfg.in_sys_port_cfg,
                                         [[S.SAI_SYSTEM_PORT_ATTR_ADMIN_STATE, True]])

    def test_invalid_lane(self):
        bad_lane = list(pytest.top.port_cfg.in_sys_port_cfg)
        bad_lane[3] = 100
        with st_utils.expect_sai_error(S.SAI_STATUS_INVALID_ATTR_VALUE_0 + S.SAI_SYSTEM_PORT_ATTR_CONFIG_INFO):
            pytest.tb.create_system_port(bad_lane)

    def test_invalid_speed(self):
        bad_speed = list(pytest.top.port_cfg.in_sys_port_cfg)
        bad_speed[4] = pytest.top.port_cfg.in_port_cfg['speed'] + 1
        with st_utils.expect_sai_error(S.SAI_STATUS_INVALID_ATTR_VALUE_0 + S.SAI_SYSTEM_PORT_ATTR_CONFIG_INFO):
            pytest.tb.create_system_port(bad_speed)

    def test_get_object_keys(self):
        obj_count, sp_oids_swig = pytest.tb.get_object_keys(S.SAI_OBJECT_TYPE_SYSTEM_PORT)
        sp_oids = [sp_oids_swig[i] for i in range(obj_count)]

        num_system_ports = pytest.tb.get_object_attr(pytest.tb.switch_id, S.SAI_SWITCH_ATTR_NUMBER_OF_SYSTEM_PORTS)
        assert num_system_ports == len(pytest.top.port_cfg.internal_sys_port_cfgs)
        switch_system_ports = pytest.tb.get_object_attr(pytest.tb.switch_id, S.SAI_SWITCH_ATTR_SYSTEM_PORT_LIST)
        assert len(switch_system_ports) == num_system_ports

        assert obj_count == num_system_ports
        assert set(sp_oids) == set(switch_system_ports)
