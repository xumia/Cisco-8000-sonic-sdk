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
import os
import sai_test_base as st_base
import time
import sai_test_utils as st_utils
from saicli import *


@pytest.fixture(scope="class")
def voq_port_attr_setup(request):
    print("\n")    # for better debug log.
    tb = st_base.sai_test_base()

    # === Setup the SAI_SWITCH_ATTR_FIRMWARE_PATH_NAME ===
    # save and remove the BASE_OUTPUT_DIR from env
    env_name = "BASE_OUTPUT_DIR"
    env_path = os.getenv(env_name, None)

    tb.log("getenv -> {} = {}".format(env_name, env_path))
    os.unsetenv(env_name)
    os.environ.pop(env_name, None)

    # check if env paths removed
    assert os.getenv(env_name, None) is None

    # setup fw_path_name for SAI_SWITCH_ATTR_FIRMWARE_PATH_NAME attribute.
    tb.fw_path_name = env_path

    # In tb.setUp(), SAI_SWITCH_ATTR_FIRMWARE_PATH_NAME attribute will be set and used during create_sai_switch().
    # === End of Setup SAI_SWITCH_ATTR_FIRMWARE_PATH_NAME ===

    # this sherman_p5_attr_test_case.json has pointer to port_mix file
    # and, tb.setUp will create ports with admin_state set to false (specified by port_mix file).
    test_case_defined_board_type = "sherman_p5_attr_test_case"

    asic_name = os.getenv('ASIC')
    if asic_name is not None:
        if asic_name.lower().startswith('gibraltar'):
            test_case_defined_board_type = "blacktip_1_attr_test_case"

    test_case_defined_board_type = os.getenv('BOARD_TYPE', test_case_defined_board_type)

    # build the tb.ports_config for cross check port_mix configuration
    SDK_ROOT = os.getenv('SDK_ROOT', os.getcwd() + "/../")
    port_config_pathname = SDK_ROOT + "/sai/test/python/attr/"
    if st_utils.is_asic_env_gibraltar():
        PORT_CFG_FILE = port_config_pathname + "sai_test_attr_port_config_gb.json"
    else:
        PORT_CFG_FILE = port_config_pathname + "sai_test_attr_port_config.json"
    tb.ports_config = st_utils.load_ports_from_json(PORT_CFG_FILE)
    st_utils.print_ports_config(tb.ports_config)

    sp_cfg_data = st_utils.PortConfig()
    port_cfgs = tb.ports_config['real_ports']
    if 'preemp_test_port' in tb.ports_config:
        port_cfgs += tb.ports_config['preemp_test_port']
    fp_sp_cfgs = [sp_cfg_data.make_sp_cfg(port_config) for port_config in port_cfgs]
    sp_cfgs = sp_cfg_data.internal_sys_port_cfgs + fp_sp_cfgs
    voq_cfg = [
        sai_attribute_t(
            SAI_SWITCH_ATTR_TYPE, SAI_SWITCH_TYPE_VOQ), sai_attribute_t(
            SAI_SWITCH_ATTR_SWITCH_ID, sp_cfg_data.VOQ_SWITCH_ID), sai_attribute_t(
                SAI_SWITCH_ATTR_MAX_SYSTEM_CORES, sp_cfg_data.max_system_cores), sai_attribute_t(
            SAI_SWITCH_ATTR_SYSTEM_PORT_CONFIG_LIST, sai_system_port_config_list_t(sp_cfgs))]

    tb.setUp(board_type=test_case_defined_board_type, optional_switch_create_time_attrs=voq_cfg)

    time.sleep(2)

    # check all port and back annotate sai_port_obj_id to tb.ports[]
    st_utils.list_active_ports(tb)
    yield tb
    tb.tearDown()


@pytest.mark.skipif(st_utils.is_sai_15x(), reason="Disabled on SAI 1.5.x")
class Test_system_port_cfg_list():
    def test_system_port_cfg_list(self, voq_port_attr_setup):
        tb = voq_port_attr_setup
        port_pifs = tb.ports.values()
        sp_oids = []
        for port_pif, port_oid in tb.ports.items():
            sp_oid = tb.get_object_attr(port_oid, SAI_PORT_ATTR_SYSTEM_PORT)
            sp_oids.append(sp_oid)
            sp_cfg = tb.get_object_attr(sp_oid, SAI_SYSTEM_PORT_ATTR_CONFIG_INFO)
            sp_pif = (sp_cfg[2] << 8) | sp_cfg[3]
            assert port_pif == sp_pif

            port_speed = tb.get_object_attr(port_oid, SAI_PORT_ATTR_SPEED)
            assert port_speed == sp_cfg[4]

            sp_port_oid = tb.get_object_attr(sp_oid, SAI_SYSTEM_PORT_ATTR_PORT)
            assert sp_port_oid == port_oid
        assert set(sp_oids) == set(tb.get_fp_system_ports())
