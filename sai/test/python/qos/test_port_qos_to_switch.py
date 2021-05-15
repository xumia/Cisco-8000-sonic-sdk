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
from device_config_changer import DeviceConfigChanger
from sai_test_base import sai_test_base
import sai_test_utils as st_utils

# This file tests a temporary SAI patch that forwards port QOS
# configuration as follows:
#
# SAI_PORT_ATTR_QOS_DSCP_TO_TC_MAP -> SAI_SWITCH_ATTR_QOS_DSCP_TO_TC_MAP
# SAI_PORT_ATTR_QOS_TC_TO_QUEUE_MAP -> SAI_SWITCH_ATTR_QOS_TC_TO_QUEUE_MAP
#
# This temporarily enables northbound controllers that require port
# QOS configuration to work, and requires enabling the device config
# 'push_port_qos_to_switch' flag to 'true'.

# TODO: Once port QOS maps are properly implemented, remove this test suite


@pytest.fixture(scope="class")
def port_qos_to_switch_enabled(tmp_dir):
    # Write out updated config file
    config_filename = str(tmp_dir / "config.json")
    config_changer = DeviceConfigChanger()
    config_changer.update_device_config({"push_port_qos_to_switch": True})
    config_changer.write_config_file(config_filename)

    # Construct test base with new config file
    pytest.tb = sai_test_base()
    pytest.tb.setUp(config_file=config_filename)
    port_cfg = st_utils.PortConfig()
    pytest.tb.configure_ports([port_cfg.in_port_cfg, port_cfg.out_port_cfg])
    yield pytest.tb
    pytest.tb.remove_ports()
    pytest.tb.tearDown()


@pytest.mark.usefixtures("port_qos_to_switch_enabled")
class TestPortQOSToSwitch:
    def setup(self):
        self.port_cfg = st_utils.PortConfig()
        self.in_port_oid = pytest.tb.ports[self.port_cfg.in_port]
        self.out_port_oid = pytest.tb.ports[self.port_cfg.out_port]

    def check_port_get_map(self, attr):
        in_port_map_oid = pytest.tb.get_object_attr(self.in_port_oid, attr)
        out_port_map_oid = pytest.tb.get_object_attr(self.out_port_oid, attr)
        assert in_port_map_oid == out_port_map_oid

    def test_get_port_qos_dscp_to_tc_map(self):
        self.check_port_get_map(SAI_PORT_ATTR_QOS_DSCP_TO_TC_MAP)

    def test_get_port_qos_tc_to_queue_map(self):
        self.check_port_get_map(SAI_PORT_ATTR_QOS_TC_TO_QUEUE_MAP)

    def check_port_set_map(self, switch_attr, port_attr, qos_map_attr, qos_map):
        orig_map_oid = pytest.tb.get_switch_attribute(switch_attr)

        qos_map_dscp_to_tc_obj_id = pytest.tb.create_qos_map(qos_map_attr, qos_map)

        pytest.tb.set_object_attr(self.in_port_oid, port_attr, qos_map_dscp_to_tc_obj_id)
        in_port_map_oid = pytest.tb.get_object_attr(self.in_port_oid, port_attr)
        out_port_map_oid = pytest.tb.get_object_attr(self.out_port_oid, port_attr)
        switch_map_oid = pytest.tb.get_switch_attribute(switch_attr)

        assert in_port_map_oid == qos_map_dscp_to_tc_obj_id
        assert out_port_map_oid == qos_map_dscp_to_tc_obj_id
        assert switch_map_oid == qos_map_dscp_to_tc_obj_id

        pytest.tb.set_switch_attribute(switch_attr, orig_map_oid)
        pytest.tb.remove_object(qos_map_dscp_to_tc_obj_id)

    def test_set_port_qos_dscp_to_tc_map(self):
        self.check_port_set_map(SAI_SWITCH_ATTR_QOS_DSCP_TO_TC_MAP,
                                SAI_PORT_ATTR_QOS_DSCP_TO_TC_MAP,
                                SAI_QOS_MAP_TYPE_DSCP_TO_TC,
                                [(10, 7), (20, 5), (5, 4)])

    def test_set_port_qos_tc_to_queue_map(self):
        self.check_port_set_map(SAI_SWITCH_ATTR_QOS_TC_TO_QUEUE_MAP,
                                SAI_PORT_ATTR_QOS_TC_TO_QUEUE_MAP,
                                SAI_QOS_MAP_TYPE_TC_TO_QUEUE,
                                [(7, 7), (5, 5), (4, 4)])
