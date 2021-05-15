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

from unified_table_wrapper_base import *
from leaba import sdk


class acl_table_wrapper_base(unified_table_wrapper_base):
    def __init__(self, device, topology, is_ipv4, is_ingress, table=None, default_entity=None):
        if table is None:
            key_profile = {
                (True, True): topology.ingress_acl_key_profile_ipv4_def,
                (True, False): topology.egress_acl_key_profile_ipv4_def,
                (False, True): topology.ingress_acl_key_profile_ipv6_def,
                (False, False): topology.egress_acl_key_profile_ipv6_def
            }[(is_ipv4, is_ingress)]
            table = device.create_acl(key_profile, topology.acl_command_profile_def)
        super().__init__(table, device, topology)
        self.packet_format = sdk.la_acl_packet_format_e_IPV4 if is_ipv4 else sdk.la_acl_packet_format_e_IPV6
        self.direction = sdk.la_acl_direction_e_INGRESS if is_ingress else sdk.la_acl_direction_e_EGRESS
        if default_entity is None:
            default_entity = topology.rx2_l3_ac.hld_obj if is_ingress else topology.tx_l3_ac_def.hld_obj
        self.default_entity = default_entity

    def attach_default(self):
        acl_group = self.default_entity.get_acl_group(self.direction)
        if acl_group is None:
            acl_group = self.device.create_acl_group()
            self.default_entity.set_acl_group(self.direction, acl_group)

        acls_on_group = acl_group.get_acls(self.packet_format)
        acls_on_group.insert(0, self.table)
        acl_group.set_acls(self.packet_format, acls_on_group)

    def detach_default(self):
        self.default_entity.clear_acl_group(self.direction)
