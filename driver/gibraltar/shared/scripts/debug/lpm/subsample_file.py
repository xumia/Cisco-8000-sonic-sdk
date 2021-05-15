#!/usr/bin/env python3
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

import argparse
import gzip
import os
import random


def subsample_file(fname, rate):
    basename, ext = os.path.splitext(fname)
    open_func = gzip.open if (ext == '.gz') else open
    out_fname = basename + '_subsampled_%d.txt' % rate

    f = open_func(fname, 'r')
    out_f = open(out_fname, 'w')

    for line in f:
        if isinstance(line, bytes):
            line = str(line, 'utf-8')
        do_sample = (random.randint(0, rate - 1) == 0)
        if do_sample:
            out_f.write(line)

    f.close()
    out_f.close()


def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("file", help="input file to subsample")
    parser.add_argument("-r", "--rate", help="sample every this much lines", type=int, default=1)
    args = parser.parse_args()

    subsample_file(args.file, args.rate)


if __name__ == '__main__':
    main()
