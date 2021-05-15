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
import py
import os
import json
import cpuinfo
from optparse import OptionParser

# Auxiliary function for messages.
# terminal_writer is a lightweight console report formatting.
def terminal_writer(text):
    py.io.TerminalWriter().line("")
    py.io.TerminalWriter().sep("-", blue=True, bold=True)
    py.io.TerminalWriter().line(text, blue=True, bold=True)
    py.io.TerminalWriter().sep("-", blue=True, bold=True)

# Auxiliary function get cpu info for benchmark json
def get_cpu_info():
    all_info = cpuinfo.get_cpu_info()
    all_info = all_info or {}
    info = {
      'vendor_id': 'unknown',
      'hardware': 'unknown',
      'brand': 'unknown'
    }
    for key in ('vendor_id', 'hardware', 'brand'):
        info[key] = all_info.get(key, 'unknown')
    return info

# Auxiliary function get field benchmarks->stats->mean from json file
def load_median_from_benchmarking_json(file_name):
    value = -1
    if os.path.isfile(file_name):
        with open(file_name, 'r') as f:
            if os.stat(file_name).st_size:
                distros_dict = json.load(f)
                if 'benchmarks' in distros_dict.keys():
                    value = distros_dict['benchmarks'][0]['stats']['median']
    return value

def benchmark_create_jenkins_plugin(reference_median_file, current_median_value_file, threshold, group_name, output_name_file):
    # Load referent value from json file
    reference_median_value = load_median_from_benchmarking_json(reference_median_file)

    # Load value from current measurement from json file
    current_median_value = load_median_from_benchmarking_json(current_median_value_file)

    if reference_median_value == -1:
        terminal_writer("Reference value in file: " + reference_median_file + " does not exist. Exit")
        exit(0)

    # Create json struct for Jenkins benchmark plugin
    root_node = dict({
    'groups' :[]
    })
    group_node = dict({
        'name': group_name,
        'tests': []
    })
    tests_node = dict({
        'name': group_name,
        'description' : get_cpu_info()['brand'] + ' ' + get_cpu_info()['vendor_id'],
        'results': []
    })
    thresholds = dict({
        'method': 'absolute',
        'minimum': round(reference_median_value*(100-threshold)/100, 3),
        'maximum': round(reference_median_value*(100+threshold)/100, 3)
    })
    test_name = os.path.splitext(os.path.basename(reference_median_file))[0]
    test_name = test_name.replace('_benchmark', '')
    results = dict({
        'name': test_name,
        'unit': 'secs', # TODO read from json file
        'value': round(current_median_value, 3),
        'thresholds': []
    })
    results['thresholds'].append(thresholds)
    tests_node['results'].append(results)
    group_node['tests'].append(tests_node)
    root_node['groups'].append(group_node)
    stats_json = json.dumps(root_node, indent=4)

    # Save json for for Jenkins benchmark plugin.
    # Path for Jenkins benchmark plugin is set in Jenkins in field inputLocation: 'driver/benchmark_results/test_*_bp.json'
    with open(output_name_file, 'w') as out:
         out.write(stats_json)
         terminal_writer("Wrote benchmark plugin data in " + os.path.abspath(os.path.dirname(output_name_file)) + '/' + os.path.basename(output_name_file))

def main():
    # Create option parser
    parser = OptionParser('python3 benchmark.py \
--reference_median_file=reference_median_value.json \
--reference_median_file=current_median_value.json \
[--threshold=<threshold_level>] \
[--group_name=pacific]')

    # Add parser options
    parser.add_option(
        '--reference_median_file',
        dest='reference_median_file',
        action='store',
        default=None,
        help='File with referent value'
    )
    parser.add_option(
        '--current_median_value_file',
        dest='current_median_value_file',
        action='store',
        default=None,
        help='File with value from current measurements'
    )
    parser.add_option(
        '--threshold',
        dest='threshold',
        action='store',
        default=5,
        help='Treshold default value is 5, that mean new value should be beetween [referenct value - 5%, referenct value - 5%]'
    )
    parser.add_option(
        '--group_name',
        dest='group_name',
        action='store',
        default='pacific',
        help='Name for group column in table on Jenkins plugin'
    )
    parser.add_option(
        '--benchmark_results_dir',
        dest='benchmark_results_dir',
        action='store',
        default=None,
        help='Directory path for result of benchmarking. This path shoud be same as path inputLocation in Jenkinsfile in Performance regression testing part'
    )

    # Set parser description
    parser.description = 'Tool for creating and collecting statistics about benchmark.'

    # Show usage help message if program has no input arguments
    if len(sys.argv) < 3:
        OptionParser.print_help(parser)
        exit(1)

    # Parse program arguments and options
    (options, args) = parser.parse_args(args=sys.argv[1:], values=None)

    # Option values
    reference_median_file = options.reference_median_file
    current_median_value_file = options.current_median_value_file
    threshold = int(options.threshold.replace("%", ""))
    group_name = options.group_name
    benchmark_results_directory = options.benchmark_results_dir + "/benchmark_results/"

    # Validation input params
    if threshold < 0 or threshold > 100:
        terminal_writer("Invalid argument")
        exit(1)

    # Setup directory and file name for json input for Jenkins benchmark plugin

    if not os.path.exists(benchmark_results_directory):
        os.makedirs(benchmark_results_directory)
    name_of_benchmark_result_file = reference_median_file.replace('_benchmark.json', '_bp.json')
    path_of_benchmark_result_file = benchmark_results_directory + os.path.basename(name_of_benchmark_result_file)

    terminal_writer("Run collect data for benchmark plugin")

    benchmark_create_jenkins_plugin(
        reference_median_file,
        current_median_value_file,
        threshold,
        group_name,
        path_of_benchmark_result_file)

if __name__ == '__main__':
    main()
