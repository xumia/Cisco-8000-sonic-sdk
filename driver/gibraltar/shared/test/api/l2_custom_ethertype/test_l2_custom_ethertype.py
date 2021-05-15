#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2021-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
from l2_custom_ethertype_base import *
import unittest


class test_l2_custom_ethertype(l2_custom_ethertype_base):

    def test_single_custom_supported_ethtype_single_tag_rx(self):
        self._test_single_custom_supported_ethtype_single_tag_rx()

    def test_custom_supported_ethtype_single_tag_rx(self):
        self._test_custom_supported_ethtype_single_tag_rx()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_custom_supported_ethtype_single_tag_rx_ive(self):
        self._test_custom_supported_ethtype_single_tag_rx_ive()

    def test_custom_supported_ethtype_single_tag_tx_eve(self):
        self._test_custom_supported_ethtype_single_tag_tx_eve()

    @unittest.skipIf(not (decor.is_gibraltar() or decor.is_asic5()),
                     "Test is applicable only on asic5 and Gibraltar as eve_drop_vlan_id_hw_table is not present on others")
    def test_custom_supported_ethtype_single_tag_rx_ive_eve_xlate(self):
        self._test_custom_supported_ethtype_single_tag_rx_ive_eve_xlate()

    def test_custom_supported_ethtype_single_tag_tx(self):
        self._test_custom_supported_ethtype_single_tag_tx()

    def test_custom_supported_ethtype_double_tag_rx(self):
        self._test_custom_supported_ethtype_double_tag_rx()

    def test_custom_supported_ethtype_double_tag_tx(self):
        self._test_custom_supported_ethtype_double_tag_tx()

    @unittest.skipIf(decor.is_asic3(), "Test is not yet enabled on GR")
    def test_single_custom_supported_ethtype_single_tag_rx_tx_on_spa(self):
        self._test_single_custom_supported_ethtype_single_tag_rx_tx_on_spa()

    def test_custom_supported_ethtype_QinQ_tunnel_rx(self):
        self._test_custom_supported_ethtype_QinQ_tunnel_rx_tx()

    def test_custom_supported_ethtype_ac_profile_change_rx(self):
        self._test_custom_supported_ethtype_ac_profile_change_rx()

    def test_custom_supported_ethtype_ac_profile_content_update_rx(self):
        self._test_custom_supported_ethtype_ac_profile_content_update_rx()

    @unittest.skipIf(decor.is_asic5(), "Not enabled on baseline for AR")
    def test_custom_supported_ethtype_selective_QinQ_tunnel_rx_tx(self):
        self._test_custom_supported_ethtype_selective_QinQ_tunnel_rx_tx()

    def test_custom_supported_ethtype_double_tag_honor_both_tpid_rx(self):
        self._test_custom_supported_ethtype_double_tag_honor_both_tpid_rx()


if __name__ == '__main__':
    unittest.main()
