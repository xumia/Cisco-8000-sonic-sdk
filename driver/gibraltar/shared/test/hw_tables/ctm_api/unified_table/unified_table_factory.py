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

#  This module houses everything necessary for instanciating a unified table wrapper.

from unified_table_wrapper_base import *
from acl_table_wrapper_base import *
from unified_table_test_case_base import *
from composite_table import *
from sw_model_table import *


class unified_table_factory:
    def NOT_SUPPORTED_STR(x, y): return "Table not supported yet."

    def NOT_A_LEGAL_NAME_STR(x, y): return "Received parameter is not a legal table name."

    # Used to create a unified table wrapper.
    #
    #  testcase  testcase on which to create the table.
    #  device    device on which to create the table.
    #  name      name of the table to be unified.
    #  mirroring if set to true a softwere model will be used, and every action on the table will also be executed on the sw model.

    @staticmethod
    def create_table(testcase, device, topology, name, mirroring):
        table = {
            "INGRESS_IPV4_SEC_TABLE": unified_table_factory.create_ingress_ipv4_sec_table,
            "INGRESS_IPV4_QOS_TABLE": unified_table_factory.create_ingress_ipv4_qos_table,
            "IPV4_LPTS_TABLE": unified_table_factory.create_ipv4_lpts_table,
            "INGRESS_IPV6_SEC_TABLE": unified_table_factory.create_ingress_ipv6_sec_table,
            "IPV6_LPTS_TABLE": unified_table_factory.create_ipv6_lpts_table,
            "INGRESS_IPV6_QOS_TABLE": unified_table_factory.create_ingress_ipv6_qos_table,
            "EGRESS_IPV4_SEC_TABLE": unified_table_factory.create_egress_ipv4_sec_table,
            "EGRESS_IPV6_SEC_TABLE": unified_table_factory.create_egress_ipv6_sec_table,
            "TERM_TABLE": unified_table_factory.NOT_SUPPORTED_STR,
            "IPV4_BGP_FS_TABLE": unified_table_factory.create_ipv4_bgp_fs_table,
            "IPV6_BGP_FS_TABLE": unified_table_factory.create_ipv6_bgp_fs_table,
            "INGRESS_IPV4_UDF_160_TABLE": unified_table_factory.NOT_SUPPORTED_STR,
            "INGRESS_IPV4_UDF_320_TABLE": unified_table_factory.NOT_SUPPORTED_STR,
            "INGRESS_IPV6_UDF_320_TABLE": unified_table_factory.NOT_SUPPORTED_STR
        }.get(name, unified_table_factory.NOT_A_LEGAL_NAME_STR)(device, topology)

        ret_val = table
        if mirroring and not isinstance(table, str):
            ret_val = composite_table(testcase, table, sw_model_table(device, topology))
        return ret_val

    @staticmethod
    def create_ingress_ipv4_sec_table(device, topology):
        table = acl_table_wrapper_base(device, topology, is_ipv4=True, is_ingress=True)
        return table

    @staticmethod
    def create_ingress_ipv4_qos_table(device, topology):
        table = acl_table_wrapper_base(device, topology, is_ipv4=True, is_ingress=True)
        device.set_acl_scaled_enabled(False)
        return table

    @staticmethod
    def create_ipv4_lpts_table(device, topology):
        lpts = device.create_lpts(sdk.lpts_type_e_LPTS_TYPE_IPV4)
        table = unified_table_wrapper_base(lpts, device, topology)
        return table

    @staticmethod
    def create_ingress_ipv6_sec_table(device, topology):
        table = acl_table_wrapper_base(device, topology, is_ipv4=False, is_ingress=True)
        return table

    @staticmethod
    def create_ipv6_lpts_table(device, topology):
        lpts = device.create_lpts(sdk.lpts_type_e_LPTS_TYPE_IPV6)
        table = unified_table_wrapper_base(lpts, device, topology)
        return table

    @staticmethod
    def create_ingress_ipv6_qos_table(device, topology):
        table = acl_table_wrapper_base(device, topology, is_ipv4=False, is_ingress=True)
        device.set_acl_scaled_enabled(False)
        return table

    @staticmethod
    def create_egress_ipv4_sec_table(device, topology):
        table = acl_table_wrapper_base(device, topology, is_ipv4=True, is_ingress=False)
        return table

    @staticmethod
    def create_egress_ipv6_sec_table(device, topology):
        table = acl_table_wrapper_base(device, topology, is_ipv4=False, is_ingress=False)
        return table

    @staticmethod
    def create_ipv4_bgp_fs_table(device, topology):
        default_entity = unified_table_test_case_base.config_data["pbripvall"]["rx_port"].hld_obj
        default_entity.set_pbr_enabled(True)
        acl = device.create_acl(
            unified_table_test_case_base.config_data["pbripv4"]["key_profile"],
            unified_table_test_case_base.config_data["pbripv4"]["command_profile"])
        table = acl_table_wrapper_base(device, topology, is_ipv4=True, is_ingress=True, table=acl, default_entity=default_entity)
        return table

    @staticmethod
    def create_ipv6_bgp_fs_table(device, topology):
        default_entity = unified_table_test_case_base.config_data["pbripvall"]["rx_port"].hld_obj
        default_entity.set_pbr_enabled(True)
        acl = device.create_acl(
            unified_table_test_case_base.config_data["pbripv6"]["acl_key_profile"],
            unified_table_test_case_base.config_data["pbripv6"]["command_profile"])
        table = acl_table_wrapper_base(device, topology, is_ipv4=False, is_ingress=True, table=acl, default_entity=default_entity)
        return table
