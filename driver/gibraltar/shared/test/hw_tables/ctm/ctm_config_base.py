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

import unittest
import lldcli
import test_hw_tables_ctmcli as ctm_cli
import decor

DEVICE_PATH = "/dev/testdev"

NUMBER_OF_SLICES = 6


@unittest.skipUnless(decor.is_gibraltar() or decor.is_pacific(), "Test intends to work only for Pacific and GB.")
class ctm_config_base(unittest.TestCase):
    LPM_NUM_BANKSETS = None
    STAND_ALONE_MODE = None

    def setUp(self):
        self.lld = lldcli.ll_device_create(0, DEVICE_PATH)
        assert self.lld is not None, "Failed to create LLD"
        assert self.STAND_ALONE_MODE is True  # TODO support LC.
        IS_LINE_CARD = not self.STAND_ALONE_MODE
        assert self.LPM_NUM_BANKSETS is not None and 1 <= self.LPM_NUM_BANKSETS <= 2
        if decor.is_gibraltar():
            self.config = ctm_cli.ctm_config_gibraltar(
                self.lld, IS_LINE_CARD, self.LPM_NUM_BANKSETS, NUMBER_OF_SLICES)
        elif decor.is_pacific():
            self.config = ctm_cli.ctm_config_pacific(self.lld, IS_LINE_CARD,
                                                     self.LPM_NUM_BANKSETS, NUMBER_OF_SLICES)
        else:
            assert False
        self.config.configure_hw()
