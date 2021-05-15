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

#  This module houses everything necessary for instanciating a unified table random entry generator.

from acl_table_entry_generator_base import *
from lpts_table_entry_generator_base import *


class table_entry_generator_factory:
    def NOT_SUPPORTED_STR(x, y): return "Table not supported yet."

    def NOT_A_LEGAL_NAME_STR(x, y): return "Received parameter is not a legal table name."

    # Used to create a unified table random entry generator.
    #
    #  testcase  testcase for which the entries will be generated.
    #  device    device for which the entries will be generated .
    #  name      name of the table for which the generator will be creating the entries.

    @staticmethod
    def create_gen(testcase, device, name):
        gen_class, is_ipv4 = {
            "INGRESS_IPV4_SEC_TABLE": (acl_table_entry_generator_base, True),
            "INGRESS_IPV4_QOS_TABLE": (acl_table_entry_generator_base, True),
            "IPV4_LPTS_TABLE": (lpts_table_entry_generator_base, True),
            "INGRESS_IPV6_SEC_TABLE": (acl_table_entry_generator_base, False),
            "IPV6_LPTS_TABLE": (lpts_table_entry_generator_base, False),
            "INGRESS_IPV6_QOS_TABLE": (acl_table_entry_generator_base, False),
            "EGRESS_IPV4_SEC_TABLE": (acl_table_entry_generator_base, True),
            "EGRESS_IPV6_SEC_TABLE": (acl_table_entry_generator_base, False),
            "TERM_TABLE": table_entry_generator_factory.NOT_SUPPORTED_STR,
            "IPV4_BGP_FS_TABLE": (acl_table_entry_generator_base, True),
            "IPV6_BGP_FS_TABLE": (acl_table_entry_generator_base, False),
            "INGRESS_IPV4_UDF_160_TABLE": table_entry_generator_factory.NOT_SUPPORTED_STR,
            "INGRESS_IPV4_UDF_320_TABLE": table_entry_generator_factory.NOT_SUPPORTED_STR,
            "INGRESS_IPV6_UDF_320_TABLE": table_entry_generator_factory.NOT_SUPPORTED_STR
        }.get(name, table_entry_generator_factory.NOT_A_LEGAL_NAME_STR)
        gen = gen_class(is_ipv4, testcase, device)
        return gen
