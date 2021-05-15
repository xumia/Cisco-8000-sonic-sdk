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


class table_entry:
    def __init__(self, key, value, descriptor=None):
        self.key = key
        self.value = value
        # If creating table entry from descriptor, which is received from the table's get() function,
        # we need to save the reference of the descriptor object. Otherwise it's underlying cpp object will be deleted.
        if descriptor:
            self.descriptor = descriptor

    # Create table_entry object from descriptor, which is received from the table's get() function
    @classmethod
    def construct_from_descriptor(cls, descriptor):
        value = descriptor.cmd if hasattr(descriptor, "cmd") else descriptor.result
        return cls(descriptor.key_val, value, descriptor)
