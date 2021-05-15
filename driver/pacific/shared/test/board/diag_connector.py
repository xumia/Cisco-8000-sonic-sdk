# BEGIN_LEGAL
#
# Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

import pexpect
import sys

PROMPT_PATTERN = '\(DSH#.\)  \[SF-.\] .*>% '


class diag_connector():
    def __init__(self):
        self.child = pexpect.spawn('dsh')
        self.child.expect(PROMPT_PATTERN)

    def exec(self, *cmd, timeout=5):
        self.child.sendline(" ".join(cmd))
        self.child.expect(PROMPT_PATTERN, timeout)
        print(self.child.before.decode("utf-8"))

    def get_prototype(self):
        self.child.sendline("show hwinfo device=X86_BOARD")
        self.child.expect(PROMPT_PATTERN)
        ver = self.child.before.strip()
        p = ver.decode().split("Board HW Rev: ")[-1]
        print(f"Get HW Rev: {p}")
        return p
