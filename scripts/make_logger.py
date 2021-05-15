#!/usr/bin/env python
# BEGIN_LEGAL
#
# Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

"""Log output of a ``make`` action:

To handle ``make -j``, this:

* Ensures each line is written atomically.

* Prefixes a unique action (process) ID to each line.
"""

import sys
from filelock import FileLock, Timeout

def locked_write(lock_file, prefix, lines, timeout):
    curr_lines_printed = 0

    try:
        with FileLock(lock_file, timeout):
            for line in lines:
                sys.stdout.write(prefix)
                sys.stdout.write(line)
                curr_lines_printed += 1 

            sys.stdout.flush()
    except Timeout:
        pass

    return lines[curr_lines_printed:]


if __name__ == '__main__':
    lock_file = sys.argv[1]
    prefix = sys.argv[2]

    # Make sure the command line is logged
    cmd = '%s\n' % (' '.join(sys.argv[3:]).replace(r'^echo.*;', ''))
    lines = [cmd]

    while True:
        line = ""
        try:
            line = sys.stdin.readline()
        except KeyboardInterrupt:
            break

        if line == "":
            break

        lines.append(line)

        # As long as more lines are coming, go on reading more lines if the lock fails.
        # This is critical for cases where multiple make_logger-s are piped together, and having all of them
        # blocked on the same lock can cause a deadlock.
        lines = locked_write(lock_file, prefix, lines, timeout=0)

    # Once there are no more inputs, write remaining content
    locked_write(lock_file, prefix, lines, timeout=60)


