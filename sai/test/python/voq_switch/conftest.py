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
from voq_topology import voq_topology


def conftest_after_topology():
    pass
    # Currently dumping all objects (inside do_warm_boot) cauases tests to fail - need to debug
    # pytest.tb.do_warm_boot(type="wb_topology")


@pytest.fixture(scope="module")
def tb_voq_setup(request):
    options = st_base.get_test_options(request)
    pytest.tb = st_base.sai_test_base(options)
    port_cfg = st_utils.PortConfig()
    voq_cfg = [
        S.sai_attribute_t(
            S.SAI_SWITCH_ATTR_TYPE, S.SAI_SWITCH_TYPE_VOQ), S.sai_attribute_t(
            S.SAI_SWITCH_ATTR_SWITCH_ID, port_cfg.VOQ_SWITCH_ID), S.sai_attribute_t(
                S.SAI_SWITCH_ATTR_MAX_SYSTEM_CORES, port_cfg.max_system_cores), S.sai_attribute_t(
                    S.SAI_SWITCH_ATTR_SYSTEM_PORT_CONFIG_LIST, S.sai_system_port_config_list_t(
                        port_cfg.internal_sys_port_cfgs))]
    pytest.tb.setUp(optional_switch_create_time_attrs=voq_cfg)
    # Verify only all internal system ports are now setup
    num_sps = pytest.tb.get_object_attr(pytest.tb.switch_id, S.SAI_SWITCH_ATTR_NUMBER_OF_SYSTEM_PORTS)
    assert num_sps > 0, "No internal system ports were created"
    assert num_sps == len(port_cfg.internal_sys_port_cfgs)
    yield pytest.tb
    pytest.tb.tearDown()


@pytest.fixture(scope="class")
def base_voq_v4_topology(tb_voq_setup):
    pytest.top = voq_topology(tb_voq_setup, "v4")


@pytest.fixture(scope="class")
def two_port_no_sp_topology(base_voq_v4_topology):
    pytest.top.configure_two_port_no_sp_topology()
    conftest_after_topology()
    yield
    pytest.top.deconfigure_two_port_no_sp_topology()


@pytest.fixture(scope="class")
def two_sp_topology(two_port_no_sp_topology):
    pytest.top.configure_two_sp_topology()
    conftest_after_topology()
    yield
    pytest.top.deconfigure_two_sp_topology()
