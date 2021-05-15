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

import sys
import unittest

#
# SVL test suite needs to be run based on the dependency of stack port packet
#
# First active switch testcases are run and stack port output packets are saved.
# Next standby switch testcases are run which picks the dependent packet saved from last active-switch-case run and validate the final output packet.
# At some scenarios, we may need to run one more time to finish standby to active scenario.
#
# The below loader logic accepts the testsuite class in order usually active, standby, activererun
#


def start(testclass0, testclass1, testclass2=None):
    full_suite = True
    arguments = sys.argv.copy()
    del arguments[0]
    # during unittest if user wants to run one specific testcase, classname.test_fun is passed as argument
    # in this scenario, unittest infra is taking care of loading the testcase and run it.
    # this argument check is to identify valid class name versus python command line option like -v -u
    for ar in arguments:
        if ((testclass0.__name__ in ar) or (testclass1.__name__ in ar) or ((testclass2 is not None) and testclass2.__name__ in ar)):
            full_suite = False
            break
    if not full_suite:
        unittest.main()
    else:
        # strict sequencing is required.  Testcases needs to be run based on the order given in start arguments
        # cannot leave the sequencing to unittest infra as at random loads, the sequencing is not guaranteed.
        loader = unittest.TestLoader()

        run_list = []
        # Add tests from first class
        run_list.append(loader.loadTestsFromTestCase(testclass0))
        # Add tests from second class
        run_list.append(loader.loadTestsFromTestCase(testclass1))
        # Add tests from third class
        if testclass2:
            run_list.append(loader.loadTestsFromTestCase(testclass2))
        # full suite
        full_suite = unittest.TestSuite(run_list)
        # Run tests
        unittest.TextTestRunner().run(full_suite)
