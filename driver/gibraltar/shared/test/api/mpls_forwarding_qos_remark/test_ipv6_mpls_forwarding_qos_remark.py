#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

import decor
import sys
import unittest
from leaba import sdk
from scapy.all import *
from php_to_ip_base import *
from php_to_mpls_base import *
from swap_base import *
from swap_double_label_base import *
import sim_utils
import topology as T
import packet_test_utils as U

load_contrib('mpls')


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_l3_ac_tagged_pipe_php_to_ip(ipv6_rx_l3_ac_tagged_pipe_test, php_to_ip_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_php_to_ip(self):
        self._test_php_to_ip()


@unittest.skipIf(True, "")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_rx_l3_ac_tagged_pipe_php_to_mpls(ipv6_rx_l3_ac_tagged_pipe_test, php_to_mpls_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_php_to_mpls(self):
        self._test_php_to_mpls()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_rx_l3_ac_tagged_pipe_swap_double_label(ipv6_rx_l3_ac_tagged_pipe_test, swap_double_label_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap_double_label(self):
        self._test_swap_double_label()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_rx_l3_ac_tagged_pipe_swap(ipv6_rx_l3_ac_tagged_pipe_test, swap_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap(self):
        self._test_swap()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_l3_ac_tagged_uniform_php_to_ip(ipv6_rx_l3_ac_tagged_uniform_test, php_to_ip_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_php_to_ip(self):
        self._test_php_to_ip()


@unittest.skipIf(True, "")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_rx_l3_ac_tagged_uniform_php_to_mpls(ipv6_rx_l3_ac_tagged_uniform_test, php_to_mpls_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_php_to_mpls(self):
        self._test_php_to_mpls()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_rx_l3_ac_tagged_uniform_swap_double_label(ipv6_rx_l3_ac_tagged_uniform_test, swap_double_label_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap_double_label(self):
        self._test_swap_double_label()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_rx_l3_ac_tagged_uniform_swap(ipv6_rx_l3_ac_tagged_uniform_test, swap_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap(self):
        self._test_swap()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_l3_ac_untagged_pipe_php_to_ip(ipv6_rx_l3_ac_untagged_pipe_test, php_to_ip_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_php_to_ip(self):
        self._test_php_to_ip()


@unittest.skipIf(True, "")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_rx_l3_ac_untagged_pipe_php_to_mpls(ipv6_rx_l3_ac_untagged_pipe_test, php_to_mpls_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_php_to_mpls(self):
        self._test_php_to_mpls()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_rx_l3_ac_untagged_pipe_swap_double_label(ipv6_rx_l3_ac_untagged_pipe_test, swap_double_label_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap_double_label(self):
        self._test_swap_double_label()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_rx_l3_ac_untagged_pipe_swap(ipv6_rx_l3_ac_untagged_pipe_test, swap_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap(self):
        self._test_swap()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_l3_ac_untagged_uniform_php_to_ip(ipv6_rx_l3_ac_untagged_uniform_test, php_to_ip_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_php_to_ip(self):
        self._test_php_to_ip()


@unittest.skipIf(True, "")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_rx_l3_ac_untagged_uniform_php_to_mpls(ipv6_rx_l3_ac_untagged_uniform_test, php_to_mpls_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_php_to_mpls(self):
        self._test_php_to_mpls()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_rx_l3_ac_untagged_uniform_swap_double_label(ipv6_rx_l3_ac_untagged_uniform_test, swap_double_label_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap_double_label(self):
        self._test_swap_double_label()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_rx_l3_ac_untagged_uniform_swap(ipv6_rx_l3_ac_untagged_uniform_test, swap_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap(self):
        self._test_swap()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_rx_svi_tagged_pipe_php_to_ip(ipv6_rx_svi_tagged_pipe_test, php_to_ip_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_php_to_ip(self):
        self._test_php_to_ip()


@unittest.skipIf(True, "")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_rx_svi_tagged_pipe_php_to_mpls(ipv6_rx_svi_tagged_pipe_test, php_to_mpls_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_php_to_mpls(self):
        self._test_php_to_mpls()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_rx_svi_tagged_pipe_swap_double_label(ipv6_rx_svi_tagged_pipe_test, swap_double_label_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap_double_label(self):
        self._test_swap_double_label()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_rx_svi_tagged_pipe_swap(ipv6_rx_svi_tagged_pipe_test, swap_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap(self):
        self._test_swap()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_rx_svi_tagged_uniform_php_to_ip(ipv6_rx_svi_tagged_uniform_test, php_to_ip_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_php_to_ip(self):
        self._test_php_to_ip()


@unittest.skipIf(True, "")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_rx_svi_tagged_uniform_php_to_mpls(ipv6_rx_svi_tagged_uniform_test, php_to_mpls_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_php_to_mpls(self):
        self._test_php_to_mpls()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_rx_svi_tagged_uniform_swap_double_label(ipv6_rx_svi_tagged_uniform_test, swap_double_label_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap_double_label(self):
        self._test_swap_double_label()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_rx_svi_tagged_uniform_swap(ipv6_rx_svi_tagged_uniform_test, swap_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap(self):
        self._test_swap()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_rx_svi_untagged_pipe_php_to_ip(ipv6_rx_svi_untagged_pipe_test, php_to_ip_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_php_to_ip(self):
        self._test_php_to_ip()


@unittest.skipIf(True, "")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_rx_svi_untagged_pipe_php_to_mpls(ipv6_rx_svi_untagged_pipe_test, php_to_mpls_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_php_to_mpls(self):
        self._test_php_to_mpls()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_rx_svi_untagged_pipe_swap_double_label(ipv6_rx_svi_untagged_pipe_test, swap_double_label_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap_double_label(self):
        self._test_swap_double_label()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_rx_svi_untagged_pipe_swap(ipv6_rx_svi_untagged_pipe_test, swap_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap(self):
        self._test_swap()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_rx_svi_untagged_uniform_php_to_ip(ipv6_rx_svi_untagged_uniform_test, php_to_ip_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_php_to_ip(self):
        self._test_php_to_ip()


@unittest.skipIf(True, "")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_rx_svi_untagged_uniform_php_to_mpls(ipv6_rx_svi_untagged_uniform_test, php_to_mpls_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_php_to_mpls(self):
        self._test_php_to_mpls()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_rx_svi_untagged_uniform_swap_double_label(ipv6_rx_svi_untagged_uniform_test, swap_double_label_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap_double_label(self):
        self._test_swap_double_label()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
@unittest.skipIf(decor.is_skip_slow(), "Workaround for slow regression")
class ipv6_rx_svi_untagged_uniform_swap(ipv6_rx_svi_untagged_uniform_test, swap_base):

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_swap(self):
        self._test_swap()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
def setUpModule():
    mpls_forwarding_qos_remark_base.initialize_device()


@unittest.skipIf(decor.is_hw_asic3(), "Test is not yet enabled on GR-HW")
def tearDownModule():
    mpls_forwarding_qos_remark_base.destroy_device()


if __name__ == '__main__':
    unittest.main()
