#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2021-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

import pytest
from saicli import *


class acl_entry_tests():

    def create_drop_entry_1_field(self, table, field, val, mask, enabled=True, priority=0):
        args = {}
        args[SAI_ACL_ENTRY_ATTR_TABLE_ID] = table
        args[SAI_ACL_ENTRY_ATTR_PRIORITY] = priority
        args[SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION] = [True, SAI_PACKET_ACTION_DROP]
        args[field] = [enabled, val, mask]
        return self.create_entry(args)

    def create_entry(self, args):
        acl_entry = pytest.tb.create_object(SAI_OBJECT_TYPE_ACL_ENTRY, args, verify=[True, False])
        return acl_entry
