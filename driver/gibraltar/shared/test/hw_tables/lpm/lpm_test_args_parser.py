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

import argparse
import sys


class lpm_tests_args_parser:

    def __init__(self):
        parser = argparse.ArgumentParser()
        parser.add_argument(
            '--enable_hbm',
            help="Set this flag to enable the HBM, Default value is enabled.",
            action='store_true', dest='enable_hbm')
        parser.add_argument('--disable_hbm', dest='enable_hbm', action='store_false',
                            help="Set this flag to disable the HBM, Default value is enabled.")
        parser.set_defaults(enable_hbm=True)
        parser.add_argument(
            '--show_progress',
            help="Set this flag to indicate whether to print progress during the tests.",
            action='store_true',
            default=False)
        parser.add_argument(
            '--shuffle',
            help="Set this flag to indicate whether to shuffle the entries, By default entries are not shuffled.",
            action='store_true',
            default=False)
        parser.add_argument(
            '--verbose',
            help="Set this flag to indicate whether to print messages, By default this flag is off.",
            action='store_true',
            default=False)
        parser.add_argument(
            '--seed',
            help="Set the test's random seed, Default is 1234.", type=int,
            default=1234)
        self.args, left_args = parser.parse_known_args()
        sys.argv[:] = sys.argv[:1] + left_args


lpm_tests_args = lpm_tests_args_parser().args
