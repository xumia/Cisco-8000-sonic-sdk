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

from table_entry_generator_base import *
import topology as T


class acl_table_entry_generator_base(table_entry_generator_base):

    DEFAULT_IPV4_ADDR = T.ipv4_addr('192.193.194.195')
    DEFAULT_IPV6_ADDR = T.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')

    def __init__(self, is_ipv4, testcase, device):
        super().__init__(is_ipv4, testcase, device)
        # la_acl_command is TCAM ACL value/payload
        self.default_cmd = sdk.la_acl_command_action()
        self.default_cmd.type = sdk.la_acl_action_type_e_COUNTER

    def _get_default_key(self):
        return self._get_default_ipv4_key() if self.is_ipv4 else self._get_default_ipv6_key()

    def _get_next_key(self):
        return self._get_next_ipv4_key() if self.is_ipv4 else self._get_next_ipv6_key()

    def _get_default_ipv4_key(self):
        k = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_IPV4_SIP
        f1.val.ipv4_sip.s_addr = acl_table_entry_generator_base.DEFAULT_IPV4_ADDR.to_num()
        f1.mask.ipv4_sip.s_addr = 0xffffffff
        k.append(f1)
        return k

    def _get_next_ipv4_key(self):
        k = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_IPV4_SIP
        f1.val.ipv4_sip.s_addr = self.get_next_ipv4_addr().to_num()
        f1.mask.ipv4_sip.s_addr = 0xffffffff
        k.append(f1)
        return k

    def _get_default_ipv6_key(self):
        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_IPV6_SIP
        def_ipv6_addr = acl_table_entry_generator_base.DEFAULT_IPV6_ADDR
        q0 = sdk.get_ipv6_addr_q0(def_ipv6_addr.hld_obj)
        q1 = sdk.get_ipv6_addr_q1(def_ipv6_addr.hld_obj)
        sdk.set_ipv6_addr(f1.val.ipv6_sip, q0, q1)
        sdk.set_ipv6_addr(f1.mask.ipv6_sip, 0xffffffffffffffff, 0xffffffffffffffff)
        k1.append(f1)
        return k1

    def _get_next_ipv6_key(self):
        k1 = []
        f1 = sdk.la_acl_field()
        f1.type = sdk.la_acl_field_type_e_IPV6_SIP
        next_ipv6_addr = self.get_next_ipv6_addr()
        q0 = sdk.get_ipv6_addr_q0(next_ipv6_addr.hld_obj)
        q1 = sdk.get_ipv6_addr_q1(next_ipv6_addr.hld_obj)
        sdk.set_ipv6_addr(f1.val.ipv6_sip, q0, q1)
        sdk.set_ipv6_addr(f1.mask.ipv6_sip, 0xffffffffffffffff, 0xffffffffffffffff)
        k1.append(f1)
        return k1

    def _get_value(self):
        return [self.default_cmd]
