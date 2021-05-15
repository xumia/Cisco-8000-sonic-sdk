#!/usr/bin/env python3
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

from leaba import sdk


def get_trap_pif_packet_counts(device, trap_name):
    counts = []

    (out_priority, out_counter, out_punt_dest, out_skip_inject_up_packets, out_skip_p2p_packets,
        out_overwrite_phb, out_tc) = device.get_trap_configuration(trap_name)

    counter_set_size = device.get_limit(sdk.limit_type_e_COUNTER_SET__MAX_PIF_COUNTER_OFFSET)

    for i in range(0, counter_set_size):
        packets, bytes = out_counter.downcast().read(i,  # sub-counter index
                                                     True,  # force_update
                                                     True)  # clear_on_read
        counts.append(packets)

    return counts
