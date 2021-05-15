# BEGIN_LEGAL
#
# Copyright (c) 2015-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

import os
import json
import argparse
import gzip

SCRIPT_DESCRIPTION = "Creates an interactive visualization (as an HTML file) of an LPM tree from an LPM dump file."

DEFAULT_CORE_INDEX = 0
DEFAULT_OUTPUT_FILE_NAME = "output.html"


def main(args):
    lpm_dump_file_name = args.dump_file_path[0]
    with gzip.open(lpm_dump_file_name) as lpm_dump_file:
        lpm_dump = json.loads(lpm_dump_file.read())

    lpm_tree_dump_string = json.dumps(lpm_dump['tree'])

    with open(args.out_file_path, "w+") as output_file:
        output_file.write(
            "<script type=text/javascript>\n\tlpm_tree_dump = '{}';\n</script>".format(lpm_tree_dump_string))
        with open(os.path.dirname(__file__) + "/lpm_visualization_template.html") as template_file:
            output_file.write(template_file.read())

    print(
        "Created visualization of the tree of the LPM dump in file \"{}\". Output is in file \"{}\"".format(
            lpm_dump_file_name,
            args.out_file_path))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=SCRIPT_DESCRIPTION)
    parser.add_argument('dump_file_path', type=str, nargs=1, help="The path of the LPM dump file.")
    parser.add_argument('out_file_path', type=str, nargs='?', default=DEFAULT_OUTPUT_FILE_NAME,
                        help="The path of the output html path to be created. The default is output.html.")

    main(parser.parse_args())
