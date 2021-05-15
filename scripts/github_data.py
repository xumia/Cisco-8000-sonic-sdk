
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
import requests
import sys
from optparse import OptionParser

return_all_labels = False

def retrieve_github_json(pr_num, github_url, access_token):
    pr_url = github_url + pr_num + "?access_token=" + access_token
    req = requests.get(pr_url)
    github_json = req.json()
    return github_json

def write_json_to_file(github_json, json_output_file):
    json_str = json.dumps(github_json, indent=2)
    f = open(json_output_file, "w+")
    f.write(json_str)
    f.close()

def print_all_labels(github_json):
    label_names = ''
    for label_list in github_json['labels']:
        label_names += label_list['name'] + " "

    print(label_names)

def find_label(github_json, label):
    label_found = False
    for label_list in github_json['labels']:
        if label_list['name'] == label:
            print("True")
            label_found = True
            break
    
    if not label_found:
        print("False")

def main():
    # create option parser
    parser = OptionParser(' \
        python3 <sdk>/scripts/github_labels.py \
        --pr=<PR #> \
        --url=<url to github repo> \
        --access_token=<ACCESS_TOKEN> \
        [--label=<LABEL>] \
        [--return_all_labels] \
        [--json_to_file=<FILE>] ')
    
    # add parser options
    parser.add_option(
        '--pr',
        dest='pr_num',
        action='store',
        default=None,
        help='Github Pull Request Number'
    )
    parser.add_option(
        '--url',
        dest='github_url',
        action='store',
        default=None,
        help='Github Repo Url'
    )
    parser.add_option(
        '--access_token',
        dest='access_token',
        action='store',
        default=None,
        help='Access Token for Github'
    )
    parser.add_option(
        '--label',
        dest='label',
        action='store',
        default=None,
        help='Github Label to search for.  Prints \"true\" if the label exists, \"false\" otherwise.'
    )
    parser.add_option(
        '--return_all_labels',
        dest='return_all_labels',
        action='store_true',
        help='Prints a list of all labels when this flag is present.'
    )
    parser.add_option(
        '--json_to_file',
        dest='json_output_file',
        action='store',
        help='Writes all json data returned from GitHub to the specified file when this flag is present.'
    )
    
    # set parser description
    parser.description = 'Jenkins Tool for determining labels associated with a Github PR.'

    # show usage help message if program has no input arguments
    if len(sys.argv) <= 3:
        OptionParser.print_help(parser)
        exit(1)

    # parse program arguments and options
    (options, args) = parser.parse_args(args=sys.argv[1:], values=None)

    # option values
    pr_num = options.pr_num
    github_url = options.github_url
    access_token = options.access_token
    label = options.label
    return_all_labels = options.return_all_labels
    json_output_file = options.json_output_file

    # check mandatory option
    if pr_num == None or access_token == None or github_url == None:
        sys.stderr.write('\nMissing some of the mandatory options (--pr_num/--url/--access_token), please check usage.\n')
        sys.stderr.flush()
        OptionParser.print_help(parser)
        exit(1)

    # check for other options
    if label == None and not return_all_labels and not json_output_file:
        sys.stderr.write('\nMissing one of --label=<LABEL>, --return_all_labels or --json_to_file options. You must include one. Please check usage.\n')
        sys.stderr.flush()
        OptionParser.print_help(parser)
        exit(1)

    if json_output_file and return_all_labels:
        sys.stderr.write('\nCannot combine both json_to_file and --return_all_labels options.\n')
        sys.stderr.flush()
        OptionParser.print_help(parser)
        exit(1)

    github_json = retrieve_github_json(pr_num, github_url, access_token)

    if json_output_file:
        write_json_to_file(github_json, json_output_file)
        print(str(json_output_file))
    elif return_all_labels:
        print_all_labels(github_json)
    else:
        find_label(github_json, label)


if __name__ == '__main__':
    main()
