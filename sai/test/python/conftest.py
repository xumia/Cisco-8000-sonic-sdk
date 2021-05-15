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
import os
import re
import saicli as S
import sai_topology as topology
import sai_test_base as st_base
from acl.acl_udk_profiles import *
from sai_test_utils import *


def pytest_addoption(parser):
    """Define additional command options"""
    parser.addoption("--debug_mode", action="store_true", default=False, help="Print TG logs, Stops after starting traffic...")
    parser.addoption("--sim", action="store_true", default=False, help="run tests on simulator")
    parser.addoption("--warmboot", action="store", default="point,topology",
                     help="Initiate warm boot at certain test points in code")
    parser.addoption("--warmboot_init", action="store_true", default=False,
                     help="Initiate test in warm boot init mode")
    parser.addoption(
        "--warmboot_shutdown_count",
        dest="wb_shutdown_count",
        default=0,
        help="Shutdown the test process after passing x number of warm boot points. Do not do warm boot on points before x")


def conftest_after_topology():
    pytest.tb.do_warm_boot(type="wb_topology")


@pytest.fixture(scope="session")
def tmp_dir(tmp_path_factory):
    '''
    Provides a Python Path object to a temporary directory for scratch work.
    '''
    return tmp_path_factory.mktemp("tmp")


@pytest.fixture(scope="module")
def tb_setup(request):
    options = st_base.get_test_options(request)
    pytest.tb = st_base.sai_test_base(options)
    if not hasattr(pytest, 'nsim_accurate') or (pytest.nsim_accurate is None or pytest.nsim_accurate == False):
        pytest.tb.setUp(nsim_accurate=False)
    else:
        pytest.tb.setUp(nsim_accurate=True)
    yield pytest.tb
    pytest.tb.tearDown()


@pytest.fixture(scope="module", params=create_v4_udk_acl_profiles())
def tb_setup_with_v4_udk_profiles(request):
    '''
    Used for test bed setup along with switch init time UDK profiles. The switch
    sai attribute list with extended ACL field list that can be programmed only
    at the time of switch create time are used. Tests are repeated for
    each element in the parameter list returned by create_v4_udk_acl_profiles()
    Profile does not contain UDF field; however contains packet header fields
    built as UDK
    '''
    options = st_base.get_test_options(request)
    pytest.tb = st_base.sai_test_base(options)
    # list of acl match attributes that are used at the create switch instance time.
    if isinstance(request.param[0], list):
        switch_attrs = []
        for acl_field_list in request.param:
            attr = S.sai_attribute_t(S.SAI_SWITCH_ATTR_EXT_ACL_FIELD_LIST, S.sai_u32_list_t(acl_field_list))
            switch_attrs.append(attr)
        pytest.tb.setUp(optional_switch_create_time_attrs=switch_attrs)
    else:
        attr = S.sai_attribute_t(S.SAI_SWITCH_ATTR_EXT_ACL_FIELD_LIST, S.sai_u32_list_t(request.param))
        pytest.tb.setUp(optional_switch_create_time_attrs=[attr])
    yield pytest.tb
    pytest.tb.tearDown()


@pytest.fixture(scope="module", params=create_v4_custom_udk_acl_profiles())
def tb_setup_with_v4_custom_udk_profiles(request):
    '''
    Used for test bed setup along with switch init time UDK profiles. The switch
    sai attribute list with extended ACL field list that can be programmed only
    at the time of switch create time are used. Tests are repeated for
    each element in the parameter list returned by create_v4_custom_udk_acl_profiles()
    create_v4_custom_udk_acl_profiles() allows to configure ACL profile with
    UDF fields (not just standard ACL fields) such as packet inner fields
    and calcualted fields.
    '''
    options = st_base.get_test_options(request)
    pytest.tb = st_base.sai_test_base(options)
    # list of acl match attributes that are used at the create switch instance time.
    if isinstance(request.param[0], list):
        switch_attrs = []
        for acl_field_list in request.param:
            attr = S.sai_attribute_t(S.SAI_SWITCH_ATTR_EXT_ACL_FIELD_LIST, S.sai_u32_list_t(acl_field_list))
            switch_attrs.append(attr)
        pytest.tb.setUp(optional_switch_create_time_attrs=switch_attrs)
    else:
        attr = S.sai_attribute_t(S.SAI_SWITCH_ATTR_EXT_ACL_FIELD_LIST, S.sai_u32_list_t(request.param))
        pytest.tb.setUp(optional_switch_create_time_attrs=[attr])
    yield pytest.tb
    pytest.tb.tearDown()


@pytest.fixture(scope="module", params=create_l2_v4_v6_udk_acl_profiles())
def tb_setup_with_l2_v4_v6_udk_profiles(request):
    '''
    Used for test bed setup along with switch init time UDK profiles. The switch
    sai attribute list with extended ACL field list that can be programmed only
    at the time of switch create time are used. Tests are repeated for
    each element in the parameter list returned by create_v4_custom_udk_acl_profiles()
    create_v4_custom_udk_acl_profiles() allows to configure ACL profile with
    UDF fields (not just standard ACL fields) such as packet inner fields
    and calcualted fields.
    '''
    pytest.request_profile = request.param_index
    options = st_base.get_test_options(request)
    pytest.tb = st_base.sai_test_base(options)
    # list of acl match attributes that are used at the create switch instance time.
    if isinstance(request.param[0], list):
        switch_attrs = []
        for acl_field_list in request.param:
            attr = S.sai_attribute_t(S.SAI_SWITCH_ATTR_EXT_ACL_FIELD_LIST, S.sai_u32_list_t(acl_field_list))
            switch_attrs.append(attr)
        pytest.tb.setUp(optional_switch_create_time_attrs=switch_attrs)
    else:
        attr = S.sai_attribute_t(S.SAI_SWITCH_ATTR_EXT_ACL_FIELD_LIST, S.sai_u32_list_t(request.param))
        pytest.tb.setUp(optional_switch_create_time_attrs=[attr])
    yield pytest.tb
    pytest.tb.tearDown()


@pytest.fixture(scope="module", params=create_l2_v4_v6_l2cid_acl_profiles())
def tb_setup_with_l2_v4_v6_l2cid_profiles(request):
    '''
    Used for test bed setup along with switch init time UDK profiles. The switch
    sai attribute list with extended ACL field list that can be programmed only
    at the time of switch create time are used. Tests are repeated for
    each element in the parameter list returned by create_v4_custom_udk_acl_profiles()
    create_v4_custom_udk_acl_profiles() allows to configure ACL profile with
    UDF fields (not just standard ACL fields) such as packet inner fields
    and calcualted fields.
    '''
    if not is_asic_env_gibraltar():
        yield
        return
    pytest.request_profile = request.param_index
    options = st_base.get_test_options(request)
    pytest.tb = st_base.sai_test_base(options)
    # list of acl match attributes that are used at the create switch instance time.
    if isinstance(request.param[0], list):
        switch_attrs = []
        for acl_field_list in request.param:
            attr = S.sai_attribute_t(S.SAI_SWITCH_ATTR_EXT_ACL_FIELD_LIST, S.sai_u32_list_t(acl_field_list))
            switch_attrs.append(attr)
        pytest.tb.setUp(optional_switch_create_time_attrs=switch_attrs)
    else:
        attr = S.sai_attribute_t(S.SAI_SWITCH_ATTR_EXT_ACL_FIELD_LIST, S.sai_u32_list_t(request.param))
        pytest.tb.setUp(optional_switch_create_time_attrs=[attr])
    yield pytest.tb
    pytest.tb.tearDown()


@pytest.fixture(scope="module", params=create_v4_udk_with_route_metadata_acl_profile())
def tb_setup_with_v4_route_user_meta_udk_profiles(request):
    '''
    Used for test bed setup along with switch init time UDK profiles. The switch
    sai attribute list with extended ACL field list that can be programmed only
    at the time of switch create time are used. Tests are repeated for
    each element in the parameter list returned by create_v4_udk_with_route_metadata_acl_profile()
    '''
    if not is_asic_env_gibraltar():
        yield
        return
    options = st_base.get_test_options(request)
    pytest.tb = st_base.sai_test_base(options)
    # list of acl match attributes that are used at the create switch instance time.
    if isinstance(request.param[0], list):
        switch_attrs = []
        for acl_field_list in request.param:
            attr = S.sai_attribute_t(S.SAI_SWITCH_ATTR_EXT_ACL_FIELD_LIST, S.sai_u32_list_t(acl_field_list))
            switch_attrs.append(attr)
        pytest.tb.setUp(optional_switch_create_time_attrs=switch_attrs)
    else:
        attr = S.sai_attribute_t(S.SAI_SWITCH_ATTR_EXT_ACL_FIELD_LIST, S.sai_u32_list_t(request.param))
        pytest.tb.setUp(optional_switch_create_time_attrs=[attr])
    yield pytest.tb
    pytest.tb.tearDown()


@pytest.fixture(scope="module", params=create_v4_udk_with_neighbor_metadata_acl_profile())
def tb_setup_with_v4_neighbor_user_meta_udk_profiles(request):
    '''
    Used for test bed setup along with switch init time UDK profiles. The switch
    sai attribute list with extended ACL field list that can be programmed only
    at the time of switch create time are used. Tests are repeated for
    each element in the parameter list returned by create_v4_udk_with_neighbor_metadata_acl_profile()
    '''
    if not is_asic_env_gibraltar():
        yield
        return
    options = st_base.get_test_options(request)
    pytest.tb = st_base.sai_test_base(options)
    # list of acl match attributes that are used at the create switch instance time.
    if isinstance(request.param[0], list):
        switch_attrs = []
        for acl_field_list in request.param:
            attr = S.sai_attribute_t(S.SAI_SWITCH_ATTR_EXT_ACL_FIELD_LIST, S.sai_u32_list_t(acl_field_list))
            switch_attrs.append(attr)
        pytest.tb.setUp(optional_switch_create_time_attrs=switch_attrs)
    else:
        attr = S.sai_attribute_t(S.SAI_SWITCH_ATTR_EXT_ACL_FIELD_LIST, S.sai_u32_list_t(request.param))
        pytest.tb.setUp(optional_switch_create_time_attrs=[attr])
    yield pytest.tb
    pytest.tb.tearDown()


@pytest.fixture(scope="module", params=create_v4_udk_with_l3_dest_metadata_acl_profile())
def tb_setup_with_v4_l3_dest_user_meta_udk_profiles(request):
    '''
    Used for test bed setup along with switch init time UDK profiles. The switch
    sai attribute list with extended ACL field list that can be programmed only
    at the time of switch create time are used. Tests are repeated for
    each element in the parameter list returned by create_v4_udk_with_l3_dest_metadata_acl_profile()
    '''
    if not is_asic_env_gibraltar():
        yield
        return
    options = st_base.get_test_options(request)
    pytest.tb = st_base.sai_test_base(options)
    # list of acl match attributes that are used at the create switch instance time.
    if isinstance(request.param[0], list):
        switch_attrs = []
        for acl_field_list in request.param:
            attr = S.sai_attribute_t(S.SAI_SWITCH_ATTR_EXT_ACL_FIELD_LIST, S.sai_u32_list_t(acl_field_list))
            switch_attrs.append(attr)
        pytest.tb.setUp(optional_switch_create_time_attrs=switch_attrs)
    else:
        attr = S.sai_attribute_t(S.SAI_SWITCH_ATTR_EXT_ACL_FIELD_LIST, S.sai_u32_list_t(request.param))
        pytest.tb.setUp(optional_switch_create_time_attrs=[attr])
    yield pytest.tb
    pytest.tb.tearDown()


@pytest.fixture(scope="class")
def base_v4_topology(tb_setup):
    pytest.top = topology.sai_topology(tb_setup, "v4")


@pytest.fixture(scope="class")
def base_v4_udk_profiles_topology(tb_setup_with_v4_udk_profiles):
    pytest.top = topology.sai_topology(tb_setup_with_v4_udk_profiles, "v4")


@pytest.fixture(scope="class")
def base_v4_custom_udk_profiles_topology(tb_setup_with_v4_custom_udk_profiles):
    pytest.top = topology.sai_topology(tb_setup_with_v4_custom_udk_profiles, "v4")


@pytest.fixture(scope="class")
def base_switching_udk_profiles_topology(tb_setup_with_l2_v4_v6_udk_profiles):
    pytest.top = topology.sai_topology(tb_setup_with_l2_v4_v6_udk_profiles, "v4")


@pytest.fixture(scope="class")
@pytest.mark.skipif(not is_asic_env_gibraltar(), reason="The test applicable only on gibraltar and later asics")
def base_switching_l2cid_profiles_topology(tb_setup_with_l2_v4_v6_l2cid_profiles):
    pytest.top = topology.sai_topology(tb_setup_with_l2_v4_v6_l2cid_profiles, "v4")


@pytest.fixture(scope="class")
@pytest.mark.skipif(not is_asic_env_gibraltar(), reason="The test applicable only on gibraltar and later asics")
def base_v4_route_user_meta_udk_profiles_topology(tb_setup_with_v4_route_user_meta_udk_profiles):
    pytest.top = topology.sai_topology(tb_setup_with_v4_route_user_meta_udk_profiles, "v4")


@pytest.fixture(scope="class")
@pytest.mark.skipif(not is_asic_env_gibraltar(), reason="The test applicable only on gibraltar and later asics")
def base_v4_neighbor_user_meta_udk_profiles_topology(tb_setup_with_v4_neighbor_user_meta_udk_profiles):
    pytest.top = topology.sai_topology(tb_setup_with_v4_neighbor_user_meta_udk_profiles, "v4")


@pytest.fixture(scope="class")
@pytest.mark.skipif(not is_asic_env_gibraltar(), reason="The test applicable only on gibraltar and later asics")
def base_v4_l3_dest_user_meta_udk_profiles_topology(tb_setup_with_v4_l3_dest_user_meta_udk_profiles):
    pytest.top = topology.sai_topology(tb_setup_with_v4_l3_dest_user_meta_udk_profiles, "v4")


@pytest.fixture(scope="class")
def base_v6_topology(tb_setup):
    pytest.top = topology.sai_topology(tb_setup, "v6")


@pytest.fixture(scope="class")
def basic_route_v4_one_port_topology(base_v4_topology):
    pytest.top.configure_basic_route_one_port_topology()
    conftest_after_topology()
    yield
    pytest.top.deconfigure_basic_route_one_port_topology()


@pytest.fixture(scope="class")
def basic_route_v4_topology(base_v4_topology):
    pytest.top.configure_basic_route_topology()
    conftest_after_topology()
    yield
    pytest.top.deconfigure_basic_route_topology()


@pytest.fixture(scope="class")
def basic_route_v4_mac_topology(base_v4_topology):
    pytest.top.configure_basic_route_rif_mac_attr_topology()
    conftest_after_topology()
    yield
    pytest.top.deconfigure_basic_route_rif_mac_attr_topology()


@pytest.fixture(scope="class")
def basic_route_v4_topology_with_udk_profiles(base_v4_udk_profiles_topology):
    pytest.top.configure_basic_route_topology()
    conftest_after_topology()
    yield
    pytest.top.deconfigure_basic_route_topology()


@pytest.fixture(scope="class")
def basic_route_v4_topology_with_custom_udk_profiles(base_v4_custom_udk_profiles_topology):
    pytest.top.configure_basic_route_topology()
    conftest_after_topology()
    yield
    pytest.top.deconfigure_basic_route_topology()


@pytest.fixture(scope="class")
def basic_switching_with_udk_profiles(base_switching_udk_profiles_topology):
    # reuse bridge topology used for mirroring
    pytest.top.configure_mirror_bridge_topology()
    conftest_after_topology()
    yield
    pytest.top.deconfigure_mirror_bridge_topology()


@pytest.fixture(scope="class")
def basic_switching_with_l2_cid_profiles(base_switching_l2cid_profiles_topology):
    if not is_asic_env_gibraltar():
        yield
        return
    pytest.top.configure_bridge_topology_with_fdb_user_meta()
    conftest_after_topology()
    yield
    pytest.top.deconfigure_bridge_topology_with_fdb_user_meta()


@pytest.fixture(scope="class")
def basic_route_v4_topology_with_route_user_meta_udk_acl(base_v4_route_user_meta_udk_profiles_topology):
    if not is_asic_env_gibraltar():
        yield
        return
    pytest.top.configure_basic_route_topology_with_l3_user_meta()
    conftest_after_topology()
    yield
    pytest.top.deconfigure_basic_route_topology_with_l3_user_meta()


@pytest.fixture(scope="class")
def basic_route_v4_topology_with_neighbor_user_meta_udk_acl(base_v4_neighbor_user_meta_udk_profiles_topology):
    if not is_asic_env_gibraltar():
        yield
        return
    pytest.top.configure_basic_route_topology_with_l3_user_meta()
    conftest_after_topology()
    yield
    pytest.top.deconfigure_basic_route_topology_with_l3_user_meta()


@pytest.fixture(scope="class")
def basic_route_v4_topology_with_l3_dest_user_meta_udk_acl(base_v4_l3_dest_user_meta_udk_profiles_topology):
    if not is_asic_env_gibraltar():
        yield
        return
    pytest.top.configure_basic_route_topology_with_l3_user_meta()
    conftest_after_topology()
    yield
    pytest.top.deconfigure_basic_route_topology_with_l3_user_meta()


@pytest.fixture(scope="class")
def basic_route_v6_topology(base_v6_topology):
    pytest.top.configure_basic_route_topology()
    conftest_after_topology()
    yield
    pytest.top.deconfigure_basic_route_topology()


@pytest.fixture(scope="class")
def dot1q_bridge_v4_topology(base_v4_topology):
    pytest.top.configure_dot1q_bridge_topology()
    conftest_after_topology()
    yield
    pytest.top.deconfigure_dot1q_bridge_topology()


@pytest.fixture(scope="class")
def dot1q_bridge_v6_topology(base_v6_topology):
    pytest.top.configure_dot1q_bridge_topology()
    conftest_after_topology()
    yield
    pytest.top.deconfigure_dot1q_bridge_topology()


@pytest.fixture(scope="class")
def dot1q_bridge_v4_lag_topology(base_v4_topology):
    pytest.top.configure_dot1q_bridge_lag_topology()
    conftest_after_topology()
    yield
    pytest.top.deconfigure_dot1q_bridge_lag_topology()


@pytest.fixture(scope="class")
def dot1q_bridge_v6_lag_topology(base_v6_topology):
    pytest.top.configure_dot1q_bridge_lag_topology()
    conftest_after_topology()
    yield
    pytest.top.deconfigure_dot1q_bridge_lag_topology()


@pytest.fixture(scope="class")
def flood_local_learn_bridge_topology(base_v4_topology):
    pytest.top.configure_flood_local_learn_bridge_topology()
    conftest_after_topology()
    yield
    pytest.top.deconfigure_flood_local_learn_bridge_topology()


@pytest.fixture(scope="class")
def flood_vlan_member_local_learn_bridge_topology(base_v4_topology):
    pytest.top.configure_vlan_member_flood_local_learn_bridge_topology()
    conftest_after_topology()
    yield
    pytest.top.deconfigure_vlan_member_flood_local_learn_bridge_topology()


@pytest.fixture(scope="class")
def flood_system_learn_bridge_topology(base_v4_topology):
    pytest.top.configure_flood_system_learn_bridge_topology()


@pytest.fixture(scope="class")
def mpls_v4_topology(base_v4_topology):
    pytest.top.configure_mpls_topology()
    conftest_after_topology()
    yield
    pytest.top.deconfigure_mpls_topology()


@pytest.fixture(scope="class")
def mpls_v6_topology(base_v6_topology):
    pytest.top.configure_mpls_topology()
    conftest_after_topology()
    yield
    pytest.top.deconfigure_mpls_topology()


@pytest.fixture(scope="class")
def next_hop_group_v4_topology(base_v4_topology):
    pytest.top.configure_next_hop_group_base_topology()
    conftest_after_topology()
    yield
    pytest.top.deconfigure_next_hop_group_base_topology()


@pytest.fixture(scope="class")
def next_hop_group_v6_topology(base_v6_topology):
    pytest.top.configure_next_hop_group_base_topology()
    conftest_after_topology()
    yield
    pytest.top.deconfigure_next_hop_group_base_topology()


@pytest.fixture(scope="class")
def svi_route_no_tag_v4_topology(base_v4_topology):
    pytest.top.configure_svi_route_topology()
    conftest_after_topology()
    yield
    pytest.top.deconfigure_svi_route_topology()


@pytest.fixture(scope="class")
def svi_route_no_tag_v6_topology(base_v6_topology):
    pytest.top.configure_svi_route_topology()
    conftest_after_topology()
    yield
    pytest.top.deconfigure_svi_route_topology()


@pytest.fixture(scope="class")
def svi_route_tag_v4_topology(base_v4_topology):
    pytest.top.configure_svi_route_topology(tag=True)
    conftest_after_topology()
    yield
    pytest.top.deconfigure_svi_route_topology()


@pytest.fixture(scope="class")
def svi_route_tag_v6_topology(base_v6_topology):
    pytest.top.configure_svi_route_topology(tag=True)
    conftest_after_topology()
    yield
    pytest.top.deconfigure_svi_route_topology()


@pytest.fixture(scope="class")
def router_lag_v4_topology(base_v4_topology):
    pytest.top.configure_router_lag_topology()
    conftest_after_topology()
    yield
    pytest.top.deconfigure_router_lag_topology()


@pytest.fixture(scope="class")
def svi_route_lag_v4_topology(base_v4_topology):
    pytest.top.configure_svi_route_lag_topology()
    conftest_after_topology()
    yield
    pytest.top.deconfigure_svi_route_lag_topology()


@pytest.fixture(scope="class")
def mirror_bridge_topology(base_v4_topology):
    pytest.top.configure_mirror_bridge_topology()
    conftest_after_topology()
    yield
    pytest.top.deconfigure_mirror_bridge_topology()


@pytest.fixture(scope="class")
def mirror_rif_topology(base_v4_topology):
    pytest.top.configure_mirror_rif_topology()
    conftest_after_topology()
    yield
    pytest.top.deconfigure_mirror_rif_topology()


@pytest.fixture(scope="class")
def mirror_bridge_rif_topology(base_v4_topology):
    pytest.top.configure_mirror_bridge_rif_topology()
    conftest_after_topology()
    yield
    pytest.top.deconfigure_mirror_bridge_rif_topology()


@pytest.fixture(scope="class")
def mirror_port_bridge_topology(base_v4_topology):
    pytest.top.configure_mirror_port_bridge_topology()
    conftest_after_topology()
    yield
    pytest.top.deconfigure_mirror_port_bridge_topology()


@pytest.fixture(scope="class")
def mirror_port_rif_topology(base_v4_topology):
    pytest.top.configure_mirror_port_rif_topology()
    conftest_after_topology()
    yield
    pytest.top.deconfigure_mirror_port_rif_topology()


@pytest.fixture(scope="class")
def mirror_port_bridge_rif_topology(base_v4_topology):
    pytest.top.configure_mirror_port_bridge_rif_topology()
    conftest_after_topology()
    yield
    pytest.top.deconfigure_mirror_port_bridge_rif_topology()


@pytest.fixture(scope="class")
def mirror_lag_bridge_topology(base_v4_topology):
    pytest.top.configure_mirror_port_bridge_topology(mirror_lag=True)
    conftest_after_topology()
    yield
    pytest.top.deconfigure_mirror_port_bridge_topology(mirror_lag=True)


@pytest.fixture(scope="class")
def mirror_lag_rif_topology(base_v4_topology):
    pytest.top.configure_mirror_port_rif_topology(mirror_lag=True)
    conftest_after_topology()
    yield
    pytest.top.deconfigure_mirror_port_rif_topology(mirror_lag=True)


@pytest.fixture(scope="class")
def mirror_lag_bridge_rif_topology(base_v4_topology):
    pytest.top.configure_mirror_port_bridge_rif_topology(mirror_lag=True)
    conftest_after_topology()
    yield
    pytest.top.deconfigure_mirror_port_bridge_rif_topology(mirror_lag=True)


class Finalizer:
    def __init__(self):
        self._cleanup = []

    # cleaners will be processed in the ordered added
    def add_cleanup(self, cleanup):
        assert callable(cleanup.clean)
        self._cleanup.append(cleanup)


@pytest.fixture(autouse=True, scope="function")
def finalizer(request):
    f = Finalizer()
    yield f
    if len(f._cleanup) > 0:
        for cleaner in f._cleanup:
            assert callable(cleaner.clean)
            cleaner.clean()


@pytest.fixture(autouse=True, scope="function")
def verify_cleanup():
    try:
        # hack to prevent it from running on snake tests
        # because they are not properly working with pytest yet
        if st_base.switch_id is not None:
            obj_types_to_check = [
                S.SAI_OBJECT_TYPE_DEBUG_COUNTER,
                S.SAI_OBJECT_TYPE_ACL_COUNTER,
                S.SAI_OBJECT_TYPE_ACL_ENTRY,
                S.SAI_OBJECT_TYPE_ACL_TABLE,
                S.SAI_OBJECT_TYPE_WRED,
                S.SAI_OBJECT_TYPE_VLAN_MEMBER,
                S.SAI_OBJECT_TYPE_VLAN,
                S.SAI_OBJECT_TYPE_BRIDGE_PORT,
                S.SAI_OBJECT_TYPE_BRIDGE,
                S.SAI_OBJECT_TYPE_ROUTER_INTERFACE,
                S.SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP,
                S.SAI_OBJECT_TYPE_HOSTIF_TRAP,
                S.SAI_OBJECT_TYPE_NEXT_HOP_GROUP,
                S.SAI_OBJECT_TYPE_NEXT_HOP_GROUP_MEMBER,
                S.SAI_OBJECT_TYPE_NEXT_HOP,
                S.SAI_OBJECT_TYPE_VIRTUAL_ROUTER,
                S.SAI_OBJECT_TYPE_SCHEDULER,
                S.SAI_OBJECT_TYPE_QOS_MAP,
                S.SAI_OBJECT_TYPE_LAG_MEMBER,
                S.SAI_OBJECT_TYPE_LAG,
                S.SAI_OBJECT_TYPE_FDB_ENTRY,
                S.SAI_OBJECT_TYPE_MIRROR_SESSION,
                S.SAI_OBJECT_TYPE_ROUTE_ENTRY,
                S.SAI_OBJECT_TYPE_NEIGHBOR_ENTRY,
                S.SAI_OBJECT_TYPE_SYSTEM_PORT]
    except BaseException:
        obj_types_to_check = []

    # get object counts before the test
    obj_numbers = {}
    for obj_type in obj_types_to_check:
        num_objs_before, obj_list_before = st_base.sai_test_base.get_object_keys(obj_type)
        obj_numbers[obj_type] = num_objs_before
    yield
    # verify object counts after the test are the same
    for obj_type in obj_types_to_check:
        num_objs_after, obj_list_after = st_base.sai_test_base.get_object_keys(obj_type)
        if num_objs_after != obj_numbers[obj_type]:
            print("object type {0} before:{1} after:{2} obj_list:{3}".format(
                obj_type, obj_numbers[obj_type], num_objs_after, obj_list_after))
        assert num_objs_after == obj_numbers[obj_type]
