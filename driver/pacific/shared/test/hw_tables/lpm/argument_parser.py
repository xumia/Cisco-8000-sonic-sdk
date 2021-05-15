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

import argparse
import sys


class argument_parser:
    def __init__(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--disable_verify',
                            help="Set to disable running verify_correctness function. By default this flag is off.",
                            action='store_true',
                            default=False)
        parser.add_argument('--random',
                            help="Set to shuffle list of prefixes. By default this flag is off.",
                            action='store_true',
                            default=False)
        parser.add_argument('--seed',
                            help="Set random seed to provided value.",
                            type=int,
                            default=1)
        parser.add_argument('--logging_level',
                            help="Set the logging level for TABLES component.",
                            type=int,
                            default=0)
        self.args, rest_args = parser.parse_known_args()
        sys.argv[:] = sys.argv[:1] + rest_args


args_parser = argument_parser().args
