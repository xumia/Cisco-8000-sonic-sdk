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

import os
from leaba import sdk
from leaba import debug
import select


def read_notifications(critical_fd, normal_fd, timeout_seconds):
    po = select.poll()  # create a poll object
    for fd in [critical_fd, normal_fd]:
        po.register(fd, select.POLLIN)  # register a file descriptor for future poll() calls
        os.set_blocking(fd, False)  # prepare for non-blocking read

    # Poll timeout is in miliseconds
    res = po.poll(timeout_seconds * 1000)
    if len(res) == 0:
        # print("\npoll() timed out - no notification descriptor available")
        return [], []

    desc_critical = read_notifications_fd(critical_fd)
    desc_normal = read_notifications_fd(normal_fd)

    return desc_critical, desc_normal


def read_notifications_fd(fd):
    sizeof = sdk.la_notification_desc.__sizeof__()
    desc_list = []
    while True:
        # A non-blocking read throws BlockingIOError when nothing is left to read
        try:
            buf = os.read(fd, sizeof)
        except BlockingIOError:
            break
        desc = sdk.la_notification_desc(bytearray(buf))
        desc_list.append(desc)

    return desc_list


def dump_notifications(device_tree, crit, norm):
    print('dumping %d notifications' % (len(crit) + len(norm)))
    for n in crit + norm:
        type_name = debug.enum_value_to_field_name(sdk, 'la_notification_type_e_', n.type)
        s = 'notification: id=%d, type=%s' % (n.id, type_name)

        reg_name = None
        bit_name = None
        blk = device_tree.get_block(n.block_id)
        if blk:
            reg = blk.get_register(n.addr)
            if reg:
                reg_name = reg.get_name()
                field = reg.get_field(n.bit_i)
                if field:
                    bit_name = field.name
        s += ', reg=%s, bit=%s' % (reg_name, bit_name)
        print(s)
