#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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


import json
import os
import re
import subprocess
import sys
import time
from collections import OrderedDict
from optparse import OptionParser
import subprocess

# Logic for enabling skipped tests is quite simple. After executing original test file,
# its output log is analyzed. If any test is skipped, then we try to enable it by simple
# string replacement:
#
# skipIf(decor.is_<specific_platform>, <message>) ===> skipIf(False, <message>)
#
# For supporting new chip, below dictionary needs to be updated with entry specifying which
# strings to replace with DONT_SKIP_STRING.
#
# Format of entry:
#   <ASIC_revision>: {
#       'all' : <skip_both_nsim_and_hw>,
#       'hw'  : <skip_hw_only>
#   }
SKIP_STRING = {
    **dict.fromkeys([
        'GIBRALTAR_A0',
        'GIBRALTAR_A1',
        'GIBRALTAR_A2'
        ], {
            'all'   : 'skipIf(decor.is_gibraltar(),',
            'hw'    : 'skipIf(decor.is_hw_gibraltar(),',
        }),
}

DONT_SKIP_STRING = 'skipIf(False,'

# map ASIC revision to platform dir
ASIC_TO_PLAFORM_DIR = {
    **dict.fromkeys([
        'GIBRALTAR_A0',
        'GIBRALTAR_A1',
        'GIBRALTAR_A2'], 'gibraltar'),
}

def get_tests(test_root, exclude_dirs):
    """
    Get dict of all tests from the specific test_root dir. Input dir is searched
    recursively for tests.

    Args:
        test_root: test root dir
        exclude_dirs: list of test dirs to exclude
    Returns:
        dict where key is test dir path, value is array of test files from that dir
    """
    tests = dict()

    sys.stdout.write('\nGetting test files from dir {}\n'.format(test_root))
    sys.stdout.flush()

    for root, dirs, files in os.walk(test_root):
        if os.path.basename(root) in exclude_dirs:
            continue
        for filename in files:
            if filename.startswith('test_') and filename.endswith('.py') and not filename.endswith('.noskip.py'):
                tests.setdefault(root, []).append(filename)

    return tests


def save_tests_json(tests, log_filepath):
    """
    Save list of discovered tests to .json file.

    Args:
        tests: dict of format {test_dir: [test1, test2, ...]}
        log_filepath: outut file path
    """
    s = json.dumps(sorted(tests.items()), indent=4)
    with open(log_filepath, 'w') as out:
        out.write(s)
    sys.stdout.write('\nList of discovered test files written to {}\n'.format(log_filepath))
    sys.stdout.flush()


def execute_test(test_file, opt_str, debug_str, test_log_file, import_dir=''):
    """
    Execute test file and save execution log to file.

    Args:
        test_file: test file to execute
        opt_str: SDK optimization level string (noopt, opt, opt2, opt3)
        debug_str: '-debug' or empty string
        test_log_file: Path to test execution log that will be created
        import_dir: Python import dir
    """
    test_name = os.path.basename(test_file)[:-3]
    test_dir = os.path.dirname(test_file)
    test_results_filename = test_log_file + '.results'

    sys.stdout.write('\n\t{} > {}'.format(os.path.basename(test_file), test_log_file))
    sys.stdout.flush()

    os.environ['PYTHONPATH'] = 'out/{0}{1}/lib:shared/test/api:out/{0}{1}/lib:shared/test/utils:examples/sanity:out/{0}{1}/pylib:{2}:{3}'.format(opt_str, debug_str, test_dir, import_dir)

    cmd = '''
import importlib
import inspect
import unittest

from unittest.runner import TextTestResult

class TextTestResultWithSuccesses(TextTestResult):
    def __init__(self, *args, **kwargs):
        super(TextTestResultWithSuccesses, self).__init__(*args, **kwargs)
        self.successes = []
    def addSuccess(self, test):
        super(TextTestResultWithSuccesses, self).addSuccess(test)
        self.successes.append(test)
    def toString(self):
        res = []
        for test in self.successes:
            res.append('PASS: ' + test.id())
        for test, info in self.failures:
            res.append('FAIL: ' + test.id())
        for test, info in self.errors:
            res.append('ERROR: ' + test.id())
        for test, skip_reason in self.skipped:
            res.append('SKIP: ' + test.id() + '; ' + skip_reason)
        return '\\n'.join(res)

module = importlib.import_module(\'{0}\')

classes = inspect.getmembers(module, lambda member: inspect.isclass(member) and member.__module__ == module.__name__)

testResultsStr = ''
for class_name, class_value in classes:

    loader = unittest.TestLoader()
    tests = loader.loadTestsFromTestCase(class_value)
    testRunner = unittest.runner.TextTestRunner(resultclass=TextTestResultWithSuccesses)
    testResults = testRunner.run(tests)
    testResultsStr += testResults.toString() + '\\n'
with open(\'{1}\', 'w') as fd:
    fd.write(testResultsStr)
'''.format(test_name, test_results_filename)

    with open(test_log_file, 'w') as fd:
        subprocess.call(['/common/pkgs/python/3.6.10/bin/python3.6', '-c', cmd], stdout=fd, stderr=fd)

    return test_results_filename


def remove_skip(test_file, no_skip_filepath, is_hw, asic):
    """
    Remove skipIf from original test file and create modified file.

    Args:
        test_file: original test file
        no_skip_filepath: path to modified file that will be created
        is_hw: True if tests are executed on HW, False otherwise
        asic: ASIC revision
    """
    with open(test_file, 'r') as inp:
        test = inp.read()

    test = test.replace(SKIP_STRING[asic]['all'], DONT_SKIP_STRING)

    if is_hw:
        test = test.replace(SKIP_STRING[asic]['hw'], DONT_SKIP_STRING)

    with open(no_skip_filepath, 'w') as outp:
        outp.write(test)


def get_test_details(test_results_file):
    """
    Grep test execution log and extract skip/pass/fail statistics.

    Args:
        test_results_file: path to file with test results
    Returns:
        Dict wtih statistics for specific test
    """
    test_node = OrderedDict({
        'total'     : 0,
        'skips'     : 0,
        'errors'    : 0,
        'fails'     : 0,
        'passes'    : 0,
        'fail_list' : [],
        'error_list': [],
        'pass_list' : [],
        'skip_map'  : {},
        'valid'     : 0
    })
    if not os.path.isfile(test_results_file):
        test_node['valid'] = 0

    else:
        with open(test_results_file, 'r') as fd:
            for line in fd:
                if line.startswith('PASS: '):
                    test_case = line.split('PASS: ')[1].split('.', 1)[1].strip()
                    if not test_case in test_node['pass_list']:
                        test_node['total'] += 1
                        test_node['passes'] += 1
                        test_node['pass_list'].append(test_case)
                elif line.startswith('FAIL: '):
                    test_case = line.split('FAIL: ')[1].split('.', 1)[1].strip()
                    if not test_case in test_node['fail_list']:
                        test_node['total'] += 1
                        test_node['fails'] += 1
                        test_node['fail_list'].append(test_case)
                elif line.startswith('ERROR: '):
                    test_case = line.split('ERROR: ')[1].split('.', 1)[1].strip()
                    if not test_case in test_node['error_list']:
                        test_node['total'] += 1
                        test_node['errors'] += 1
                        test_node['error_list'].append(test_case)
                elif line.startswith('SKIP: '):
                    test_case_seg, skip_reason_seg = line.split(';', 1)
                    test_case = test_case_seg.split('SKIP: ')[1].split('.', 1)[1].strip()
                    skip_reason = skip_reason_seg.strip()
                    if not test_case in test_node['skip_map']:
                        test_node['total'] += 1
                        test_node['skips'] += 1
                        test_node['skip_map'][test_case] = skip_reason

        test_node['valid'] = (test_node['total'] != 0)

    return test_node


def dump_stats_to_json(stats, output):
    """
    Write tests' statistics to .json file.

    Args:
        stats: dict with statistics
        output: output file path
    """
    stats_json = json.dumps(stats, indent=6)
    with open(output, 'w') as out:
        out.write(stats_json)


def dump_stats_to_csv(stats, output):
    """
    Write tests' statistics to .csv file.

    Args:
        stats: dict with statistics
        output: output file path
    """
    # counters only for skipped tests
    total_skipped = 0
    total_skipped_failed = 0
    total_skipped_passed = 0

    # counters for all tests after skips removed
    total = 0
    total_failed_or_disabled = 0
    total_passed = 0

    with open(output, 'w') as out:
        out.write('Test directory,Test file,Test case,Can be enabled,Disabled,,Tried to enable cnt,Failed cnt,Passed cnt,Disabled reason\n\n')

        for test_dir in stats:
            dir_skipped = 0
            dir_skipped_failed = 0
            dir_skipped_passed = 0

            for test_file in stats[test_dir]:
                orig = stats[test_dir][test_file]['orig']

                # if test contained one or more 'skip'
                if 'no_skips' in stats[test_dir][test_file]:
                    no_skips = stats[test_dir][test_file]['no_skips']

                    if no_skips['valid']:
                        skip_list_diff = list(set(orig['skip_map'].keys()) - set(no_skips['skip_map'].keys()))
                        pass_list_diff = list(set(no_skips['pass_list']) - set(orig['pass_list']))
                        fail_list_diff = list(set(no_skips['error_list'] + no_skips['fail_list']) - set(orig['error_list'] + orig['fail_list']))

                        # if removing skips caused some test to fail but it was passing originally,
                        # mark all tests that we tried to enable as failed
                        for failed_test in fail_list_diff:
                            if failed_test in orig['pass_list']:
                                pass_list_diff = []
                                fail_list_diff = skip_list_diff
                                break

                        test_skip_diff = len(skip_list_diff)
                        test_pass_diff = len(pass_list_diff)
                        test_fail_diff = len(fail_list_diff)

                        # log tests that fail after removing skip
                        # add reasons why each of them is skipped in the first place
                        for fail_test in fail_list_diff:
                            skip_reason = orig['skip_map'][fail_test]
                            out.write('{},{},{},,,,1,1,0,"{}"\n'.format(test_dir, test_file, fail_test, skip_reason))

                        # log tests that pass after removing skip
                        for pass_test in pass_list_diff:
                            out.write('{},{},{},1,,,1,0,1\n'.format(test_dir, test_file, pass_test))

                        # log tests that still remain skipped for whatever reason
                        # add skip reason
                        for skip_test, skip_reason in no_skips['skip_map'].items():
                            out.write('{},{},{},,1,,,,,"{}"\n'.format(test_dir, test_file, skip_test, skip_reason))

                        test_total = orig['total']
                        test_skipped = orig['skips'] - test_skip_diff
                        test_failed = orig['errors'] + orig['fails'] + test_fail_diff
                        test_passed = orig['passes'] + test_pass_diff

                        dir_skipped += test_skip_diff
                        dir_skipped_failed += test_fail_diff
                        dir_skipped_passed += test_pass_diff

                    else:
                        # if data is invalid, assume all skipped tests failed
                        for skip_test, skip_reason in orig['skip_map'].items():
                            out.write('{},{},{},,,,1,1,0,"{}"\n'.format(test_dir, test_file, skip_test, skip_reason))

                        test_total = orig['total']
                        test_skipped = orig['skips']
                        test_failed = orig['errors'] + orig['fails']
                        test_passed = orig['passes']

                        dir_skipped += test_skipped
                        dir_skipped_failed += test_skipped
                        dir_skipped_passed += 0

                    total += test_total
                    total_failed_or_disabled += test_failed + test_skipped
                    total_passed += test_passed

                else:
                    total += orig['total']
                    total_failed_or_disabled += orig['errors'] + orig['fails']
                    total_passed += orig['passes']

            #out.write(',,,,,DIR TOTAL,{},{},{}\n\n'.format(dir_skipped, dir_skipped_failed, dir_skipped_passed))

            total_skipped += dir_skipped
            total_skipped_failed += dir_skipped_failed
            total_skipped_passed += dir_skipped_passed

        # total skipped stats
        out.write('\n,,,,,TOTAL,{},{},{}\n'.format(total_skipped, total_skipped_failed, total_skipped_passed))

        # total stats after skips removed
        out.write('\n{0},{0},,,,{0},{0},{0},{0}\n'.format('============'))
        out.write('Total executed,{}\n'.format(total))
        out.write('Total passed,{}\n'.format(total_passed))
        out.write('Total failed or disabled,{}\n'.format(total_failed_or_disabled))

    sys.stdout.write('\nTotal number of tests is {} , from which (after removing skips):\n'.format(total))
    sys.stdout.write('\t{} pass\n'.format(total_passed))
    sys.stdout.write('\t{} fail or still disabled\n'.format(total_failed_or_disabled))

    sys.stdout.write('\nTotal number of skipped tests is {} , from which:\n'.format(total_skipped))
    sys.stdout.write('\t{} pass\n'.format(total_skipped_passed))
    sys.stdout.write('\t{} fail\n'.format(total_skipped_failed))

    sys.stdout.write('\nFor more details please check file {}\n'.format(output))
    sys.stdout.flush()


def main():

    # create option parser
    parser = OptionParser('cd <sdk>/driver/<platform>/ ; \
python3 <sdk>/scripts/get_skipped_tests_stat.py \
--asic=<ASIC> \
--test_dir=<TEST_DIR> \
[--log_dir=<LOG_DIR>] \
[--opt=<OPT_LEVEL>] \
[--debug] \
[--hw] \
[--restart_script=<RESTART_SCRIPT>] \
[--exclude_dirs=<EXCLUDE_DIRS_LIST>]')

    # add parser options
    parser.add_option(
        '--asic',
        dest='asic',
        action='store',
        default=None,
        help='ASIC revision.'
    )
    parser.add_option(
        '--test_dir',
        dest='test_dir',
        action='store',
        default=None,
        help='Test directory path. This option is mandatory.'
    )
    parser.add_option(
        '--log_dir',
        dest='log_dir',
        action='store',
        default='./LOGS',
        help='Log directory path. Default is LOGS dir in working dir.'
    )
    parser.add_option(
        '--opt',
        dest='opt_level',
        action='store',
        type='int',
        default=0,
        help='Optimization level. Must match OPT parameter from SDK build. Default is 0.'
    )
    parser.add_option(
        '--debug',
        dest='debug',
        action='store_true',
        default=False,
        help='Debug flag. Add this option if SDK is built with option DEBUG=1. Default is False;.'
    )
    parser.add_option(
        '--hw',
        dest='hardware',
        action='store_true',
        default=False,
        help='Add this flag if tests need to be executed on HW device. Default is False.'
    )
    parser.add_option(
        '--restart_script',
        dest='restart_script',
        action='store',
        default=None,
        help='ASIC restart script.'
    )
    parser.add_option(
        '--exclude_dirs',
        dest='exclude_dirs',
        action='store',
        default='',
        help='List of test dirs to exclude. Directory names must be separated by \',\' delimiter.'
    )
    parser.add_option(
        '--npsuite_root',
        dest='npsuite_root',
        action='store',
        default='',
        help='Path to the npsuite release directory'
    )

    # set parser description
    parser.description = 'Tool for running skipped tests and collecting statistics. Must be ran from platform dir.'

    # show usage help message if program has no input arguments
    if len(sys.argv) == 1:
        OptionParser.print_help(parser)
        exit(1)

    # parse program arguments and options
    (options, args) = parser.parse_args(args=sys.argv[1:], values=None)

    # option values
    asic = options.asic
    test_root_dir = options.test_dir
    test_logs_dir = options.log_dir
    opt = options.opt_level
    is_debug = options.debug
    is_hardware = options.hardware
    restart_script = options.restart_script
    exclude_dirs = options.exclude_dirs.split(',')
    npsuite_root = options.npsuite_root

    # check mandatory option
    if test_root_dir == None or asic == None:
        sys.stderr.write('\nMissing some of the mandatory options (--test_dir/--asic), please check usage.\n')
        sys.stderr.flush()
        OptionParser.print_help(parser)
        exit(1)

    # create log dir if does not exist
    if not os.path.exists(test_logs_dir):
        os.makedirs(test_logs_dir)

    sdk_root = os.path.abspath(os.path.dirname(sys.argv[0])).replace('/scripts', '')

    sdk_device_name = '/dev/uio0' if is_hardware else ''
    opt_str = 'opt{}'.format(opt) if opt else 'noopt'
    debug_str = '-debug' if is_debug else ''
    asic_rev = asic if asic else ''
    restart = restart_script if (is_hardware and restart_script) else ''
    platform = ASIC_TO_PLAFORM_DIR[asic_rev]

    os.environ['ASIC'] = "{}".format(asic_rev)
    os.environ['ASIC_RESTART_SCRIPT']= "{}".format(restart)
    os.environ['SDK_DEVICE_NAME']="{}".format(sdk_device_name)
    os.environ['NSIM_SOURCE_PATH']="{}/npl/cisco_router".format(sdk_root)
    os.environ['NSIM_LEABA_DEFINED_FOLDER']="{}/devices/{}/leaba_defined".format(sdk_root, platform)
    os.environ['NPSUITE_LBR_PATH']="out/{}{}/res/{}/hw_definitions/npsuite_lbr.json".format(opt_str, debug_str, platform)
    os.environ['LD_LIBRARY_PATH']="/common/pkgs/gcc/4.9.4/lib64:out/{}{}/lib:".format(opt_str, debug_str)
    os.environ['BASE_OUTPUT_DIR']="out/{}{}".format(opt_str, debug_str)
    os.environ['NPSUITE_ROOT']=npsuite_root
    
    tests = get_tests(test_root_dir, exclude_dirs)

    test_json_filepath = os.path.join(test_logs_dir, 'tests.json')
    save_tests_json(tests, test_json_filepath)

    sys.stdout.write('\nStart executing tests:\n')
    sys.stdout.flush()

    stats = OrderedDict()

    timestamp = str(time.time()).split(".")[0]

    # iterate through test dirs
    for test_dir, test_files in sorted(tests.items()):
        stats[test_dir] = OrderedDict()

        sys.stdout.write('\n\n' + test_dir + '\n')
        sys.stdout.flush()

        # create log dir for test dir
        test_dir_log_dir = os.path.join(test_logs_dir, os.path.basename(test_dir))
        if not os.path.exists(test_dir_log_dir):
            os.makedirs(test_dir_log_dir)

        # execute tests from dir one by one
        for test_file in test_files:
            stats[test_dir][test_file] = OrderedDict()

            test_filepath = os.path.join(test_dir, test_file)
            test_log_file = os.path.join(test_dir_log_dir, test_file + '.log')

            test_results_file = execute_test(test_filepath, opt_str, debug_str, test_log_file)
            stats[test_dir][test_file]['orig'] = get_test_details(test_results_file)

            # if some tests are skipped, try to remove skipIf and re-run tests
            if stats[test_dir][test_file]['orig']['skips'] > 0:
                sys.stdout.write(' (has skips)')
                sys.stdout.flush()

                # remove skips from test file and write new file <test_file>.<timestamp>.noskip.py
                no_skip_filepath = os.path.join(test_dir_log_dir, test_file)[:-3] + '_' + str(timestamp) + '_noskip.py'
                remove_skip(test_filepath, no_skip_filepath, is_hardware, asic)
                test_log_file = os.path.join(test_dir_log_dir, test_file + '_noskip.log')

                import_dir = os.path.dirname(test_filepath)
                test_results_file = execute_test(no_skip_filepath, opt_str, debug_str, test_log_file, import_dir)
                stats[test_dir][test_file]['no_skips'] = get_test_details(test_results_file)

                # remove tmp test file with skips removed
                os.remove(no_skip_filepath)

    sys.stdout.write('\n\nFINISH!\n')
    sys.stdout.flush()

    # dump summary to json file
    json_summary_filepath = os.path.join(test_logs_dir, 'summary.json')
    dump_stats_to_json(stats, json_summary_filepath)

    # dump summary to csv file
    csv_summary_filepath = os.path.join(test_logs_dir, 'summary.csv')
    dump_stats_to_csv(stats, csv_summary_filepath)


if __name__ == '__main__':
    main()
