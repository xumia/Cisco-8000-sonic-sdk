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

import topology as T
import random
import ipaddress
from table_entry import *
from leaba import sdk


class table_entry_generator_base:
    def __init__(self, is_ipv4, testcase, device):
        self.is_ipv4 = is_ipv4
        self.testcase = testcase
        self.device = device
        self.next_ipv4_addr = 1
        self.next_ipv6_addr = 1

    # brief Generate a table_entry.
    def generate_default_entry(self):
        key = self._get_default_key()
        value = self._get_value()
        ret_val = self.construct_entry(key, value)
        return ret_val

    # brief Generate next unique table_entry.
    def generate_next_entry(self):
        key = self._get_next_key()
        value = self._get_value()
        ret_val = self.construct_entry(key, value)
        return ret_val

    # Get random IPv4 address.
    #
    # return an instance of topology::ipv4_addr.

    def get_random_ipv4_addr(self):
        ip_str = ".".join(str(randint(0, 255)) for _ in range(4))
        ip = T.ipv4_addr(ip_str)
        return ip

    # Get random IPv6 address.
    #
    # return an instance of topology::ipv4_addr.
    def get_random_ipv6_addr(self):
        ip_str = ':'.join('{:x}'.format(random.randint(0, 2**16 - 1)) for _ in range(8))
        ip = T.ipv6_addr(ip_str)
        return ip

    # Get IPV4 address, whose hex value is bigger by 1 then the ip address returned by the previous call.
    #
    # return an instance of topology::ipv4_addr.
    # Note may throw an exception if called more times than the number of unique addresses it can generate.
    def get_next_ipv4_addr(self):
        ip_str = str(ipaddress.IPv4Address(self.next_ipv4_addr))
        self.next_ipv4_addr += 1
        ip = T.ipv4_addr(ip_str)
        return ip

    # Get IPV6 address, whose hex value is bigger by 1 then the ip address returned by the previous call.
    #
    # return an instance of topology::ipv6_addr.
    # Note may throw an exception if called more times than the number of unique addresses it can generate.
    def get_next_ipv6_addr(self):
        ip_str = str(ipaddress.IPv6Address(self.next_ipv6_addr))
        self.next_ipv6_addr += 1
        ip = T.ipv6_addr(ip_str)
        return ip

    # reset the source of unique entries generation
    def reset(self):
        self.next_ipv4_addr = 1
        self.next_ipv6_addr = 1

    # construct a table_entry from key val pair. This way each generator can define on its own which
    # part of the key value will be compared agains the same part of other table_entry created by the same generator.
    #
    # return an instance of table_entry.
    def construct_entry(self, key, val):
        return table_entry(key, val)
