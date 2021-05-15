#!/usr/bin/env python3
#
# A simple script that screen scrapes the timestamps out of two SDK make log
# and prints the time differences between them for various tests e.g.:
#
# $ compare-sdk-make-logs.py consoleText.17 consoleText.20 --txt
#
#     TestName                                                                         Platform   Type       NewTest    Run1:'consoleText.1' Run2:'consoleText.2' Difference(secs)
#     --------                                                                         --------   ----       -------    ----                 ----                 ---------------
#     test/api/warm_boot/ip_routing/test_auto_warm_boot_ipv4_l3_ac_routing.py          unknown    Api Test   No         17.41                6616.68              6599.28
#     test/api/warm_boot/counters/test_warm_boot_l3_counters.py                        unknown    Api Test   No         15.19                2368.92              2353.74
#     pacific shared/test/api/traps/test_l2cp.py                                       pacific    Valgrind   No         13239.98             15300.32             2060.35
#     pacific shared/test/api/pfc/test_hw_pfc.py                                       pacific    Valgrind   No         12085.52             13935.72             1850.21
#     gibraltar shared/test/api/warm_boot/ip_routing/test_auto_warm_boot_ipv4_l3_ac_ro gibraltar  Py Test    No         5.46                 1616.29              1610.84
#     test/api/warm_boot/meters/test_warm_boot_cdp_meters.py                           unknown    Api Test   No         17.42                1393.37              1375.95
#     test/api/warm_boot/ctm/test_warm_boot_ctm.py                                     unknown    Api Test   No         17.44                1003.4               985.97
#     gibraltar shared/test/api/warm_boot/counters/test_warm_boot_l3_counters.py       gibraltar  Py Test    No         4.57                 921.44               916.88
#     ...
#     Total delta in seconds 145932.16
#
# Default output is in csv format
#

import argparse
import re
import sys
import time
import logging
import math
from datetime import datetime

program_name = sys.argv[0]
arguments = sys.argv[1:]

class ParseSdkLogs():
    def __init__(self, txt, debug):
        self.txt = txt
        self.debug = debug
        self.run1_test_duration = {}
        self.run2_test_duration = {}
        self.run1 = ""
        self.run2 = ""
        self.run1_end = None
        self.run2_end = None
        self.py_valgrind_start_test = re.compile("^\\[(........................)\\] Py Valgrind Testing: (.*) \.\.\.")
        self.py_valgrind_end_test   = re.compile("^\\[(........................)\\] Py Valgrind (.*) \.\.\. PASSED")
        self.py_start_test          = re.compile("^\\[(........................)\\] Py Testing: (.*) \.\.\.")
        self.py_end_test            = re.compile("^\\[(........................)\\] Py (.*) \.\.\. PASSED")
        self.app_start_test         = re.compile("^\\[(........................)\\] App Testing: (.*) \.\.\.")
        self.app_end_test           = re.compile("^\\[(........................)\\] App (.*) \.\.\. PASSED")
        self.api_start_test         = re.compile("^\\[(........................)\\] Api Testing driver (.*) \.\.\.")
        self.api_end_test           = re.compile("^\\[(........................)\\].*-u (.*) -v.*\.passed")
        self.date_test              = re.compile("^\\[(........................)\\].*")
        self.txt_format = "{:<80.80} {:<10} {:<10} {:<10} {:<20} {:<20} {:<16} {}"

    def formatter(self, verbosity=logging.INFO):
        format_string = "%(asctime)s "
        datefmt = "%H:%M:%S"
        format_string += "%(levelname)4s: "
        format_string += "%(message)s"
        return logging.Formatter(format_string, datefmt=datefmt)

    def enable_logger(self):
        self.logging_handler = logging.StreamHandler()
        self.logging_handler.setFormatter(self.formatter(logging.DEBUG))
        self.logging_handler.setFormatter(self.formatter(logging.INFO))
        self.logging_handler.setFormatter(self.formatter(logging.ERROR))

        self.logger = logging.getLogger(__name__)
        self.logger.addHandler(self.logging_handler)

        if self.debug:
            self.logging_handler.setLevel(logging.DEBUG)
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logging_handler.setLevel(logging.INFO)
            self.logger.setLevel(logging.INFO)

        self.logger.propagate = False  # avoid multiple logs:

    def test_platform(self, test_name):
        platforms = [ "pacific", "gibraltar", "argon", "palladium", "graphene", "sai" ]
        for p in platforms:
            if test_name.startswith(p + " "):
                return p
        return "unknown"

    def process(self, test_log_name):
        with open(test_log_name) as fp:
            test_duration = {}
            start_ts = {}
            end_ts = {}

            for line in fp:
                line = line.rstrip()

                ret = self.date_test.match(line)
                if ret:
                    date = ret.group(1)
                    mytime = datetime.strptime(date, "%Y-%m-%dT%H:%M:%S.%fZ")
                    last_ts = time.mktime(mytime.timetuple())
                    last_ts += mytime.microsecond / 1000000.0

                #
                # Try to match with the start of a test
                #
                ret = self.api_start_test.match(line)
                test_type = "Api Test"
                if not ret:
                    ret = self.py_valgrind_start_test.match(line)
                    test_type = "Valgrind"
                    if not ret:
                        ret = self.py_start_test.match(line)
                        test_type = "Py Test"
                        if not ret:
                            ret = self.app_start_test.match(line)
                            test_type = "App Test"
                if ret:
                    #
                    # Found a test start
                    #
                    date = ret.group(1)
                    test_name = ret.group(2)
                    test_platform = self.test_platform(test_name)

                    if self.debug:
                        if test_name == "palladium shared/test/api/mac_port/test_mac_port_fast_tune.py":
                            self.logger.debug("Test {} started  {}".format(test_name, date))

                    mytime = datetime.strptime(date, "%Y-%m-%dT%H:%M:%S.%fZ")
                    ts = time.mktime(mytime.timetuple())
                    ts += mytime.microsecond / 1000000.0
                    start_ts[test_name] = (test_name, test_platform, test_type, date, ts)

                    if test_name not in test_duration:
                        test_duration[test_name] = (test_name, test_platform, test_type, date, "", -1)

                #
                # Try to match with the end of a test
                #
                ret = self.api_end_test.match(line)
                test_type = "Api Test"
                if not ret:
                    ret = self.py_valgrind_end_test.match(line)
                    test_type = "Valgrind"
                    if not ret:
                        ret = self.py_end_test.match(line)
                        test_type = "Py Test"
                        if not ret:
                            ret = self.app_end_test.match(line)
                            test_type = "App Test"
                if ret:
                    #
                    # Found a test end
                    #
                    date = ret.group(1)
                    test_name = ret.group(2)
                    test_platform = self.test_platform(test_name)

                    #
                    # We have an end to this test, remove the start marker we added to catch tests that do not end
                    #
                    if test_name in test_duration:
                        (run_test_name, run_test_platform, run_test_type, run_test_start_date, run_test_end_date, run_duration) = test_duration[test_name]
                        if run_duration == -1:
                            del test_duration[test_name]

                    if self.debug:
                        if test_name == "palladium shared/test/api/mac_port/test_mac_port_fast_tune.py":
                            self.logger.debug("Test {} stopped  {}".format(test_name, date))

                    mytime = datetime.strptime(date, "%Y-%m-%dT%H:%M:%S.%fZ")
                    ts = time.mktime(mytime.timetuple())
                    ts += mytime.microsecond / 1000000.0

                    if test_name in start_ts:
                        end_ts[test_name] = (test_name, test_platform, test_type, date, ts)

                        (test_name, test_platform, test_type, test_start_date, test_start_ts) = start_ts[test_name]
                        (test_name, test_platform, test_type, test_end_date, test_end_ts) = end_ts[test_name]
                        duration = test_end_ts - test_start_ts

                        if test_name in test_duration is not None:
                            (run1_test_name, run1_test_platform, run1_test_type, run1_test_start_date, run1_test_end_date, run1_duration) = test_duration[test_name]
                            if self.debug:
                                if test_name == "palladium shared/test/api/mac_port/test_mac_port_fast_tune.py":
                                    self.logger.debug("Test duration already exists for {} started {} stopped {} duration {}".format(test_name, test_start_date, test_end_date, duration))
                                    self.logger.debug("Previous                         {} started {} stopped {} duration {}".format(run1_test_name, run1_test_start_date, run1_test_end_date, run1_duration))
                            duration += run1_duration

                        test_duration[test_name] = (test_name, test_platform, test_type, test_start_date, test_end_date, duration)
                        if self.debug:
                            if test_name == "palladium shared/test/api/mac_port/test_mac_port_fast_tune.py":
                                self.logger.debug("Test {} duration {} seconds".format(test_name, duration))

            if not bool(self.run1_test_duration):
                self.run1_test_duration = test_duration.copy()
                self.run1_test_log_name = test_log_name
                self.run1_end = last_ts
            else:
                self.run2_test_duration = test_duration.copy()
                self.run2_test_log_name = test_log_name
                self.run2_end = last_ts

    def dump_output(self):
        if bool(self.run1_test_duration) and bool(self.run2_test_duration):
            total_delta = 0

            if self.txt:
                print(self.txt_format.format("TestName", "Platform", "Type", "NewTest", "Run1:" + self.run1_test_log_name, "Run2:" + self.run2_test_log_name, "Difference(secs)", "Note"))
                print(self.txt_format.format("--------", "--------", "----", "-------", "----", "----", "----------------", "----"))
            else:
                print("TestName,Platform,Type,NewTest?,Run1:'{}'(secs),Run2:'{}'(secs),Difference(secs),Note".format(self.run1_test_log_name, self.run2_test_log_name))

            out = []
            for k,v in self.run2_test_duration.items():
                if k in self.run1_test_duration:
                    (run1_test_name, run1_test_platform, run1_test_type, run1_test_start_date, run1_test_end_date, run1_duration) = self.run1_test_duration[k]
                    (run2_test_name, run2_test_platform, run2_test_type, run2_test_start_date, run2_test_end_date, run2_duration) = v
                    if run1_duration == -1 and run2_duration == -1:
                        mytime = datetime.strptime(run1_test_start_date, "%Y-%m-%dT%H:%M:%S.%fZ")
                        ts = time.mktime(mytime.timetuple())
                        ts += mytime.microsecond / 1000000.0
                        run1_duration = self.run1_end - ts
                        run1_duration = math.ceil(run1_duration*100)/100

                        mytime = datetime.strptime(run2_test_start_date, "%Y-%m-%dT%H:%M:%S.%fZ")
                        ts = time.mktime(mytime.timetuple())
                        ts += mytime.microsecond / 1000000.0
                        run2_duration = self.run2_end - ts
                        run2_duration = math.ceil(run2_duration*100)/100

                        out.append((run2_test_name, run2_test_platform, run2_test_type, "No", run1_duration, run2_duration, delta, "Neither test finished"))
                        self.run1_test_duration[k] = None
                        self.run2_test_duration[k] = None
                    else:
                        delta = run2_duration - run1_duration
                        delta = math.ceil(delta*100)/100
                        run1_duration = math.ceil(run1_duration*100)/100
                        run2_duration = math.ceil(run2_duration*100)/100
                        total_delta += delta
                        out.append((run2_test_name, run2_test_platform, run2_test_type, "No", run1_duration, run2_duration, delta, ""))
                        self.run1_test_duration[k] = None
                        self.run2_test_duration[k] = None
                else:
                    (run2_test_name, run2_test_platform, run2_test_type, run2_test_start_date, run2_test_end_date, run2_duration) = v
                    if run2_duration != -1:
                        run2_duration = math.ceil(run2_duration*100)/100
                        out.append((run2_test_name, run2_test_platform, run2_test_type, "Run 2 only", 0, run2_duration, 0, ""))
                    else:
                        mytime = datetime.strptime(run2_test_start_date, "%Y-%m-%dT%H:%M:%S.%fZ")
                        ts = time.mktime(mytime.timetuple())
                        ts += mytime.microsecond / 1000000.0
                        run2_duration = self.run2_end - ts
                        run2_duration = math.ceil(run2_duration*100)/100
                        out.append((run2_test_name, run2_test_platform, run2_test_type, "Run 2 only", 0, run2_duration, run2_duration, "Run 2 did not finish"))
                    self.run2_test_duration[k] = None

            for k,v in self.run1_test_duration.items():
                if not k in self.run2_test_duration:
                    (run1_test_name, run1_test_platform, run1_test_type, run1_test_start_date, run1_test_end_date, run1_duration) = v
                    if run1_duration != -1:
                        run1_duration = math.ceil(run1_duration*100)/100
                        out.append((run1_test_name, run1_test_platform, run1_test_type, "Run 1 only", run1_duration, 0, 0, ""))
                    else:
                        mytime = datetime.strptime(run1_test_start_date, "%Y-%m-%dT%H:%M:%S.%fZ")
                        ts = time.mktime(mytime.timetuple())
                        ts += mytime.microsecond / 1000000.0
                        run1_duration = self.run1_end - ts
                        run1_duration = math.ceil(run1_duration*100)/100
                        out.append((run1_test_name, run1_test_platform, run1_test_type, "Run 1 only", run1_duration, 0, run1_duration, "Run 1 did not finish"))
                    self.run1_test_duration[k] = None

            sorted_by_delta = reversed(sorted(out, key=lambda tup: tup[6]))
            for o in sorted_by_delta:
                test_name, test_platform, test_type, newtest, duration1, duration2, delta, note = o
                if self.txt:
                    print(self.txt_format.format(test_name, test_platform, test_type, newtest, duration1, duration2, delta, note))
                else:
                    print("'{}',{},{},{},{},{},{},{}".format(test_name, test_platform, test_type, newtest, duration1, duration2, delta, note))

            if self.txt:
                total_delta = math.ceil(total_delta*100)/100
                print("Total delta in seconds {}".format(total_delta))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Compares log times between two SDK logs")
    parser.add_argument('file1', type=str, help="SDK log, run 1 output text file")
    parser.add_argument('file2', type=str, help="SDK log, run 2 output text file")
    parser.add_argument("--txt", dest='txt', default=False, action='store_true', help="Output as text instead of csv")
    parser.add_argument("--debug", dest='debug', default=False, action='store_true', help="Enable debugs")

    args = parser.parse_args()

    l = ParseSdkLogs(txt=args.txt, debug=args.debug)
    l.enable_logger()
    l.process(args.file1)
    l.process(args.file2)
    l.dump_output()
