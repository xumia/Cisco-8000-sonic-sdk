#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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


from leaba import sdk
import decor

###
# VOQ allocator
###

NATIVE_VOQ_SET_SIZE = 16
if decor.is_asic3():
    NUM_SLICES_PER_DEVICE = 8
else:
    NUM_SLICES_PER_DEVICE = 6
NUM_IFGS_PER_SLICE = 2

MAX_VOQS_PER_SLICE_IN_STANDALONE_DEVICE = 24576
NUM_NATIVE_VOQ_SETS = MAX_VOQS_PER_SLICE_IN_STANDALONE_DEVICE / NATIVE_VOQ_SET_SIZE
MAX_VCSS_PER_IFG_IN_STANDALONE_DEVICE = MAX_VOQS_PER_SLICE_IN_STANDALONE_DEVICE / 2
STANDALONE_DEV = [sdk.la_slice_mode_e_NETWORK] * NUM_SLICES_PER_DEVICE

NPL_LOCAL_DEVICE_ID = 0x1ff


class allocation:
    def __init__(self, voq_base, vsc_vec):
        self.voq_base = voq_base
        self.vsc_vec = vsc_vec


class allocator:
    def __init__(self, base_voq, base_vsc, slice_modes):
        if base_voq * NATIVE_VOQ_SET_SIZE >= MAX_VOQS_PER_SLICE_IN_STANDALONE_DEVICE:
            raise Exception

        if ((base_vsc + NUM_IFGS_PER_SLICE) * NATIVE_VOQ_SET_SIZE) > MAX_VCSS_PER_IFG_IN_STANDALONE_DEVICE:
            raise Exception

        self.slice_modes = slice_modes
        self.base_voq = base_voq * NATIVE_VOQ_SET_SIZE
        self.next_voq = self.base_voq

        self.base_vsc = []
        base_vsc_run = base_vsc * NATIVE_VOQ_SET_SIZE
        for slice_id in range(len(self.slice_modes)):
            if self.slice_modes[slice_id] == sdk.la_slice_mode_e_NETWORK:
                self.base_vsc.append(base_vsc_run)
                base_vsc_run = base_vsc_run + NATIVE_VOQ_SET_SIZE
            else:
                self.base_vsc.append(sdk.LA_VSC_GID_INVALID)

        self.next_vsc = self.base_vsc

    def allocate(self, voq_set_size):
        if self.next_voq - self.base_voq >= NATIVE_VOQ_SET_SIZE:
            raise Exception

        retval = allocation(self.next_voq, self.next_vsc)
        self.next_voq += voq_set_size
        new_next_vsc = []
        for slice_id in range(len(self.slice_modes)):
            if self.slice_modes[slice_id] == sdk.la_slice_mode_e_NETWORK:
                new_next_vsc.append(self.next_vsc[slice_id] + voq_set_size)
            else:
                new_next_vsc.append(sdk.LA_VSC_GID_INVALID)

        self.next_vsc = new_next_vsc
        return retval


class voq_allocator:
    def __init__(self, first_base_voq=192, slice_modes=STANDALONE_DEV):
        self.reset()
        self.slice_modes = slice_modes
        self.next_free_base_voq = int(first_base_voq / NATIVE_VOQ_SET_SIZE)
        self.next_free_base_vsc = [self.next_free_base_voq] * NUM_SLICES_PER_DEVICE

    def reset(self):
        self.allocators = {}

    def allocate_voq_set(self, dest_slice, dest_ifg, voq_set_size, dest_device=NPL_LOCAL_DEVICE_ID):
        try:
            ns = self.allocators[(dest_device, dest_slice, dest_ifg)]
            next_allocation = ns.allocate(voq_set_size)
        except Exception:
            pass
        else:
            return True, next_allocation.voq_base, next_allocation.vsc_vec
        # if we got here then either there was no allocator for the specified
        # slice or the existing allocator is full. create a new allocator
        # in either case.
        base_vsc = self.next_free_base_vsc[dest_slice]
        try:
            new_allocator = allocator(self.next_free_base_voq, base_vsc, self.slice_modes)
        except Exception:        # we're out of VOQs or VSCs
            return False, None, None

        self.next_free_base_voq += 1

        self.next_free_base_vsc[dest_slice] += NUM_SLICES_PER_DEVICE

        # no need to keep the previous allocator since allocations are never reclaimed in this test
        self.allocators[(dest_device, dest_slice, dest_ifg)] = new_allocator
        next_allocation = new_allocator.allocate(voq_set_size)

        return True, next_allocation.voq_base, next_allocation.vsc_vec
