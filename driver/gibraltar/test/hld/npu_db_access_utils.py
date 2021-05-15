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

import sys
import json
import re
import gzip
import time

from scapy.all import *
from packet_test_defs import *
import npu_host_packet_gen
from binascii import hexlify, unhexlify
import test_nsim_providercli as nsim
import test_racli as ra
import nplapicli as nplapi

from leaba import sdk
from leaba import debug
import lldcli
import topology


class npu_db_access_header_template:

    def npu_db_access_app_get_common_header(num_of_lu_macros):

        header = "{:04b}".format(num_of_lu_macros) + "{:04b}".format(0)
        return "{:02x}".format(int(header, 2))

    def npu_db_access_app_get_term_lu_header(bucket_a_lu_dest,
                                             bucket_b_lu_dest,
                                             bucket_c_lu_dest,
                                             bucket_d_lu_dest,
                                             bucket_a_result_dest,
                                             bucket_b_result_dest,
                                             bucket_c_result_dest,
                                             bucket_d_result_dest,
                                             bucket_a_key_selector,
                                             bucket_b_key_selector,
                                             bucket_c_key_selector,
                                             bucket_d_key_selector):

        header = "{:04b}".format(bucket_a_lu_dest) + \
                 "{:04b}".format(bucket_b_lu_dest) + \
                 "{:04b}".format(bucket_c_lu_dest) + \
                 "{:04b}".format(bucket_d_lu_dest) + \
                 "{:04b}".format(bucket_a_result_dest) + \
                 "{:04b}".format(bucket_b_result_dest) + \
                 "{:04b}".format(bucket_c_result_dest) + \
                 "{:04b}".format(bucket_d_result_dest) + \
                 "{:06b}".format(bucket_a_key_selector) +\
                 "{:06b}".format(bucket_b_key_selector) +\
                 "{:06b}".format(bucket_c_key_selector) +\
                 "{:06b}".format(bucket_d_key_selector)

        return "{:014x}".format(int(header, 2))

    def npu_db_access_app_get_fwd_lu_header(bucket_a_lu_dest,
                                            bucket_b_lu_dest,
                                            bucket_c_lu_dest,
                                            bucket_d_lu_dest,
                                            bucket_a_result_dest,
                                            bucket_b_result_dest,
                                            bucket_c_result_dest,
                                            bucket_d_result_dest,
                                            bucket_a_key_selector,
                                            bucket_b_key_selector,
                                            bucket_c_key_selector,
                                            bucket_d_key_selector):

        header = "{:04b}".format(bucket_a_lu_dest) + \
                 "{:04b}".format(bucket_b_lu_dest) + \
                 "{:03b}".format(bucket_c_lu_dest) + \
                 "{:02b}".format(bucket_d_lu_dest) + \
                 "{:03b}".format(bucket_a_result_dest) + \
                 "{:02b}".format(bucket_b_result_dest) + \
                 "{:02b}".format(bucket_c_result_dest) + \
                 "{:02b}".format(bucket_d_result_dest) + \
                 "{:02b}".format(0) + \
                 "{:06b}".format(bucket_a_key_selector) +\
                 "{:06b}".format(bucket_b_key_selector) +\
                 "{:06b}".format(bucket_c_key_selector) +\
                 "{:06b}".format(bucket_d_key_selector)

        return "{:012x}".format(int(header, 2))

    def npu_db_access_app_get_tran_lu_header(bucket_a_lu_dest,
                                             bucket_b_lu_dest,
                                             bucket_c_lu_dest,
                                             bucket_d_lu_dest,
                                             bucket_a_result_dest,
                                             bucket_b_result_dest,
                                             bucket_c_result_dest,
                                             bucket_d_result_dest,
                                             bucket_a_key_selector,
                                             bucket_b_key_selector,
                                             bucket_c_key_selector,
                                             bucket_d_key_selector):

        header = "{:04b}".format(bucket_a_lu_dest) + \
                 "{:04b}".format(bucket_b_lu_dest) + \
                 "{:03b}".format(bucket_c_lu_dest) + \
                 "{:04b}".format(bucket_d_lu_dest) + \
                 "{:03b}".format(bucket_a_result_dest) + \
                 "{:03b}".format(bucket_b_result_dest) + \
                 "{:03b}".format(bucket_c_result_dest) + \
                 "{:03b}".format(bucket_d_result_dest) + \
                 "{:05b}".format(0) + \
                 "{:06b}".format(bucket_a_key_selector) +\
                 "{:06b}".format(bucket_b_key_selector) +\
                 "{:06b}".format(bucket_c_key_selector) +\
                 "{:06b}".format(bucket_d_key_selector)

        return "{:014x}".format(int(header, 2))
