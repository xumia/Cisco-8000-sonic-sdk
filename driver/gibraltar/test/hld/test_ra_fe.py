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

import sys

import unittest
from leaba import sdk

import hld_sim_utils
import sim_utils
from scapy.all import *
import topology as T
from packet_test_utils import *
import rtl_test_utils
from ip_test_base import *

import pdb
import nplapicli


class ra_unit_test(unittest.TestCase):

    socket_port = 0
    use_socket = False
    restore_mems_init = False       # Used for run-restore option with socket
    restore_full_init = False       # Used for run-restore option with socket
    skip_arc_microcode = False      # Used for skipping ARC microcode - used for init sequence debug only
    debug_mode = False

    def setUp(self):
        pass

    def tearDown(self):
        if (ra_unit_test.debug_mode):
            import pdb
            print('Enterring debug mode. use \'interact\' to enter interactive mode')
            pdb.set_trace()
        if getattr(self, 'is_rtl', False):
            # Inform RTL to stop simulation
            self.device.sim.stop_simulation()
            # Set logger off (before destroy - no need the destroy writes on RTL)
            self.device.logger_off()

    def block_filter_getter(self, ll_device):
        if self.is_full_chip:
            return []
        if ll_device.is_pacific():
            return rtl_test_utils.pacific_npu_blocks
        if ll_device.is_gibraltar():
            return rtl_test_utils.gb_npu_blocks
        return []

    def test_fabric_init_flow(self):
        self.device = hld_sim_utils.create_ra_device('/dev/testdev/rtl',
                                                     dev_id=1,
                                                     use_socket=ra_unit_test.use_socket,
                                                     port=ra_unit_test.socket_port,
                                                     slice_modes=hld_sim_utils.FABRIC_ELEMENT_DEV,
                                                     create_sim=True,
                                                     inject_from_npu_host=False,
                                                     restore_full_init=ra_unit_test.restore_full_init,
                                                     restore_mems_init=ra_unit_test.restore_mems_init,
                                                     skip_arc_microcode=ra_unit_test.skip_arc_microcode,
                                                     add_inject_up_header_if_inject_from_npuh=True)


if __name__ == '__main__':
    unittest.main()
