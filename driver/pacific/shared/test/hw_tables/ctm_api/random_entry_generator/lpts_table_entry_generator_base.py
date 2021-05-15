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


import topology
from table_entry_generator_base import *


class lpts_table_entry_generator_base(table_entry_generator_base):

    DEFAULT_SIP_IPV4 = topology.ipv4_addr('192.193.194.195')
    DEFAULT_SIP_IPV6 = topology.ipv6_addr('2222:0db8:0a0b:12f0:0000:0000:0000:2222')

    def __init__(self, is_ipv4, testcase, device):
        super().__init__(is_ipv4, testcase, device)
        self.meter = None
        self.counter_or_meter = None
        self.is_ipv4 = is_ipv4

    def _get_default_key(self):
        return self._get_default_ipv4_key() if self.is_ipv4 else self._get_default_ipv6_key()

    def _get_next_key(self):
        return self._get_next_ipv4_key() if self.is_ipv4 else self._get_next_ipv6_key()

    def _get_default_ipv4_key(self):
        k0 = sdk.la_lpts_key()
        k0.type = sdk.lpts_type_e_LPTS_TYPE_IPV4
        k0.val.ipv4.sip.s_addr = lpts_table_entry_generator_base.DEFAULT_SIP_IPV4.to_num()
        k0.mask.ipv4.sip.s_addr = 0xffffffff
        return k0

    def _get_next_ipv4_key(self):
        k0 = sdk.la_lpts_key()
        k0.type = sdk.lpts_type_e_LPTS_TYPE_IPV4
        k0.val.ipv4.sip.s_addr = self.get_next_ipv4_addr().to_num()
        k0.mask.ipv4.sip.s_addr = 0xffffffff
        return k0

    def _get_default_ipv6_key(self):
        SIP = lpts_table_entry_generator_base.DEFAULT_SIP_IPV6
        k0 = sdk.la_lpts_key()
        k0.type = sdk.lpts_type_e_LPTS_TYPE_IPV6
        r0 = sdk.get_ipv6_addr_q0(SIP.hld_obj)
        r1 = sdk.get_ipv6_addr_q1(SIP.hld_obj)
        sdk.set_ipv6_addr(k0.val.ipv6.sip, r0, r1)
        sdk.set_ipv6_addr(k0.mask.ipv6.sip, 0xffffffffffffffff, 0xffffffffffffffff)
        return k0

    def _get_next_ipv6_key(self):
        next_ipv6_addr = self.get_next_ipv6_addr()
        k0 = sdk.la_lpts_key()
        k0.type = sdk.lpts_type_e_LPTS_TYPE_IPV6
        r0 = sdk.get_ipv6_addr_q0(next_ipv6_addr.hld_obj)
        r1 = sdk.get_ipv6_addr_q1(next_ipv6_addr.hld_obj)
        sdk.set_ipv6_addr(k0.val.ipv6.sip, r0, r1)
        sdk.set_ipv6_addr(k0.mask.ipv6.sip, 0xffffffffffffffff, 0xffffffffffffffff)
        return k0

    def _get_value(self, is_entry_meter=True):
        result = sdk.la_lpts_result()
        result.flow_type = 11
        result.punt_code = 120
        result.tc = 0
        result.dest = self.testcase.punt_dest2
        result.meter = None
        if self.meter is not None:
            if is_entry_meter is True:
                result.counter_or_meter = self.meter
            else:
                result.meter = self.meter

        if self.counter_or_meter is None:
            self.counter_or_meter = topology.create_meter_set(self.testcase, self.device, is_aggregate=True)
        result.counter_or_meter = self.counter_or_meter
        return result
