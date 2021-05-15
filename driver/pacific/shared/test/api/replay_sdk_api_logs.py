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
import os
import argparse
import time
from leaba import sdk
from log_replay import log_replay
import sim_utils


def main(api_log_file, replay_cmd_file, replay_log_file, skip_init, verbosity):
    rep = log_replay()
    device_id = rep.get_device_id(api_log_file)
    rep.create_replay_commands(device_id, api_log_file, replay_cmd_file, replay_on_nsim=True, verbose=verbosity)
    if os.path.exists(replay_log_file):
        print('Error: Replay API log file %s already exists.' % (replay_log_file))
        return
    rep.set_replay_log_file(replay_log_file)
    device = sim_utils.create_test_device('/dev/testdev', device_id, initialize=False, enable_logging=False)
    rep.replay_commands(replay_cmd_file, device)
    sdk.la_flush_log()
    rep.compare_in_out_logs(api_log_file, replay_log_file)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='SDK API log parse and replay')
    parser.add_argument('-v', '--verbosity', type=int, default=0, choices=[0, 1, 2, 3], required=False, help='verbose/debug mode')
    parser.add_argument('-s', '--skip_init', action="store_true", help='Skip API logs during device initialization')
    parser.add_argument('api_log_file', help='Input API log file to replay.')
    parser.add_argument('replay_cmd_file', help='Output file with replay commands.')
    parser.add_argument('replay_log_file', help='Output API log file for replay commands.')
    args = parser.parse_args()
    print(args)
    start_time = time.time()
    main(args.api_log_file, args.replay_cmd_file, args.replay_log_file, args.skip_init, args.verbosity)
    print('--- Run time %s seconds ---' % (time.time() - start_time), file=sys.stderr)
