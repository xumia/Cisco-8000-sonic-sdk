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

import time
import unittest
from leaba import sdk

import sim_utils
import mac_port_helper

MAX_IFG_ID = 1
MAX_SLICE_ID = 5


class device_serdes():
    """
    Handler for SerDes in a system - contains slice, IFG and SerDes.
    Can do basic operations/calculation.

    Helper class for building mixes.
    """

    def __init__(self, device, slice_ind, ifg, serdes):
        self.device = device
        self.slice = -1
        self._minimal_slice_ind = slice_ind
        self._slice_ind = 100  # some bad value
        self.ifg = ifg
        self.serdes = serdes
        self.set_slice(self._minimal_slice_ind)

    def set_slice(self, slice_ind):
        valid_slices = self.device.get_used_slices()
        self._slice_ind = slice_ind
        was_wraped = False
        if self._slice_ind >= len(valid_slices):
            was_wraped = True
            self._slice_ind = self._minimal_slice_ind
        self.slice = valid_slices[self._slice_ind]
        return was_wraped

    def __wrap__(self):
        was_wraped = False
        if self.serdes >= self.__serdes_count__():
            self.serdes = 0
            self.ifg += 1
            if self.ifg > MAX_IFG_ID:
                self.ifg = 0
                was_wraped = self.set_slice(self._slice_ind + 1)
        return was_wraped

    def __serdes_count__(self):
        serdes_source = self.device.get_serdes_source(self.slice, self.ifg)
        return(len(serdes_source))

    def find_first_valid(self, serdes_count):
        """
        Find first valid SerDes for port with serdes_count
        """
        if (self.serdes % serdes_count) != 0:
            # Align the first SerDes
            self.serdes = (int(self.serdes / serdes_count) + 1) * serdes_count
        if (self.serdes + serdes_count - 1) >= self.__serdes_count__():
            # Check no overflow
            self.serdes += serdes_count

        return self.__wrap__()

    def advance(self, serdes_count):
        """
        Advance the SerDes by serdes_count
        """
        self.serdes += serdes_count
        return self.__wrap__()


class loopback_base(unittest.TestCase):
    def setUp(self):
        self.device_id = 0
        self.mph = mac_port_helper.mac_port_helper()
        self.mph.verbose = False

    def tearDown(self):
        self.mph.teardown()
        self.device.tearDown()
