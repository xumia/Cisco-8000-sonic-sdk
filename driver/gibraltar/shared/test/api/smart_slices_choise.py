# BEGIN_LEGAL
#
# Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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


def rechoose_odd_inject_slice(this, device):
    # MATILDA_SAVE -- need review
    if this.INJECT_SLICE not in device.get_used_slices():
        this.INJECT_SLICE = T.choose_active_slices(device, this.INJECT_SLICE, [1, 3, 5])


def rechoose_even_inject_slice(this, device):
    # MATILDA_SAVE -- need review
    if this.INJECT_SLICE not in device.get_used_slices():
        this.INJECT_SLICE = T.choose_active_slices(device, this.INJECT_SLICE, [0, 2, 4])


def rechoose_punt_inject_slice(this, device):
    # MATILDA_SAVE -- need review
    if this.PUNT_INJECT_SLICE not in device.get_used_slices():
        this.PUNT_INJECT_SLICE = T.choose_active_slices(device, this.PUNT_INJECT_SLICE, [1, 3, 5])


def rechoose_PI_slices(this, device):
    # MATILDA_SAVE -- need review
    if this.PI_SLICE not in device.get_used_slices():
        this.PI_SLICE = T.choose_active_slices(device, this.PI_SLICE, [1, 3, 5])
