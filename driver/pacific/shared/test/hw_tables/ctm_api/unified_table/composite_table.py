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

from collections import OrderedDict


class composite_table:
    def __init__(self, unittest, hw_table=None, sw_table=None):
        self.unittest = unittest
        self.elements = OrderedDict([("hw_table", hw_table), ("sw_table", sw_table)])

    def _assertAllEqual(self, elem_list):
        for element in elem_list:
            self.unittest.assertEqual(elem_list[0], element)

    def _do_for_each(self, action_name, *args):
        ret_vals = []
        for element_name, element in self.elements.items():
            action = getattr(element, action_name)
            ret_vals.append(action(*args))
        self._assertAllEqual(ret_vals)
        return ret_vals[0]

    # brief Get number of entries in the table.
    #
    # out_count           ACE count.
    def do_get_count(self):
        return self._do_for_each('do_get_count')

    # Create and add an ACE to the end of the ACL.
    #
    # entry contains the key and value to be appended.
    def do_append(self, entry):
        return self._do_for_each('do_append', entry)

    # Add an ACE to an ACL at a specified position.
    ##
    # position    ACE index in the ACL. If it's greater than ACL size, then it will be appended.
    # entry contains the key and value to be inserted.
    def do_insert(self, position, entry):
        return self._do_for_each('do_insert', position, entry)

    # Update an ACE of an ACL at a specified position.
    ##
    # position    ACE index in the ACL.
    # entry contains the key and value to be set.
    def do_set_entry(self, position, entry):
        return self._do_for_each('do_set_entry', position, entry)

    # Erase an ACE at a specific location from the ACL.
    ##
    # position            The position of the ACE in the ACL.
    def do_erase(self, position):
        return self._do_for_each('do_erase', position)

    # Remove an LPTS entry at a specific location and also move all the following entries
    # up to fill the hole.
    ##
    # position            The position of the LPTS entry.
    # return              Entry from position.
    def do_pop(self, position):
        return self._do_for_each('do_pop', position)

    # Delete all ACE's from the ACL.
    def do_clear(self):
        return self._do_for_each('do_clear')

    # Retrieve an ACE from ACL's specific position.
    ##
    # position            The position of the ACE in the ACL.
    def do_get(self, position):
        return self._do_for_each('do_get', position)
