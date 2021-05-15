#!/usr/bin/python
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

#
# Untabify a file.

import os
import sys

SPACES_PER_TAB = 4

def untabify(filename):
    if not os.path.isfile(filename):
        print("Error: file %s does not exist." % filename)
        exit(1)

    lines = open(filename, 'r').readlines()
    os.remove(filename)

    f = open(filename, 'w')
    for line in lines:
        line = untabify_line(line)
        f.write(line)

    f.close()

def untabify_line(line):
    first_find = line.find('\t')

    while first_find != -1:
        num_of_spaces = 4 - (first_find % SPACES_PER_TAB)
        spaces = ' ' * num_of_spaces
        line = line.replace('\t', spaces, 1)

        first_find = line.find('\t')

    return line

if __name__ == '__main__':
    untabify(sys.argv[1])