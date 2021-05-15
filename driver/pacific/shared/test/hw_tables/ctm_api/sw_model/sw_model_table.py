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

#  A sw representation of the memory, without any constraints.


class sw_model_table:
    def __init__(self, device, topology):
        self._init_empty_container()

    # brief Get number of entries in the table.
    #
    # out_count           ACE count.
    def do_get_count(self):
        return len(self.container)

    # Create and add an ACE to the end of the ACL.
    #
    # entry contains the key and value to be set
    def do_append(self, entry):
        self.container.append(entry)

    # Add an ACE to an ACL at a specified position.
    ##
    # position    ACE index in the ACL. If it's greater than ACL size, then it will be appended.
    # entry contains the key and value to be set
    def do_insert(self, position, entry):
        container_size = len(self.container)
        if position > container_size:
            position = container_size
        self.container.insert(position, entry)

    # Update an ACE of an ACL at a specified position.
    ##
    # position    ACE index in the ACL.
    # entry contains the key and value to be set
    def do_set_entry(self, position, entry):
        if position < len(self.container):
            self.container[position] = entry
            return True
        else:
            return False

    # Erase an ACE at a specific location from the ACL.
    ##
    # position            The position of the ACE in the ACL.
    def do_erase(self, position):
        if position < len(self.container):
            del self.container[position]
            return True
        else:
            return False

    # Remove an LPTS entry at a specific location and also move all the following entries
    # up to fill the hole.
    ##
    # position            The position of the LPTS entry.
    # return              Entry from position.
    def do_pop(self, position):
        # TODO
        raise NotImplementedError

    # Delete all ACE's from the ACL.
    def do_clear(self):
        self._init_empty_container()

    # Retrieve an ACE from ACL's specific position.
    ##
    # position            The position of the ACE in the ACL.
    def do_get(self, position):
        retval = None
        if position < len(self.container):
            retval = self.container[position]
        return retval

    def _init_empty_container(self):
        self.container = []
