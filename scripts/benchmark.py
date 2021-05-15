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
import os
import py
import pytest
import inspect


# Global variable to collect object for benchmarking
object_for_behchmark = []

# A decorator that should be used when benchmarking a whole class or function
def benchmark(obj):
    if is_benchmark():
        global object_for_behchmark
        object_for_behchmark.append(obj)
    return obj

# Auxiliary function for checking is it run for benchmarking
def is_benchmark():
    return __file__ in sys.argv

# Auxiliary function for messages.
# terminal_writer is a lightweight console report formatting.
def terminal_writer(text):
    py.io.TerminalWriter().line("")
    py.io.TerminalWriter().sep("-", blue=True, bold=True)
    py.io.TerminalWriter().line(text, blue=True, bold=True)
    py.io.TerminalWriter().sep("-", blue=True, bold=True)

# Auxiliary function for execute unit test.
def run_unittest():
    terminal_writer("Run unit tests")
    for x in object_for_behchmark:
        terminal_writer(os.getloadavg())
        if inspect.isclass(x):
            terminal_writer("class")
            unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(x))

        if inspect.isfunction(x):
            terminal_writer("function")
            # TODO
            # unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(x).addTest(x.__globals__['__name__']()(x.__name__)))

def get_run_rounds():
    iterations = os.environ.get('BENCHMARK_ROUNDS')
    if iterations is None:
        return 1
    return int(iterations) if iterations.isdigit() else 1

# Main function for pytest-benchmark
def test_benchmark_main(benchmark):
    if len(object_for_behchmark):
        benchmark.pedantic(run_unittest, iterations=1, rounds=get_run_rounds())
