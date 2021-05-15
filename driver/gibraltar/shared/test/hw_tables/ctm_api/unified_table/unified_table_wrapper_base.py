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

#  Unified wrapper base class.

from table_entry import *


class unified_table_wrapper_base:
    # param table - either of la_acl or of la_lpts type
    def __init__(self, table, device, topology):
        self.table = table
        self.device = device
        self.topology = topology

    # brief Get number of entries in the table.
    #
    # out_count           ACE count.
    def do_get_count(self):
        return self.table.get_count()

    # Create and add an ACE to the end of the ACL.
    #
    # entry contains the key and value to be appended.
    def do_append(self, entry):
        self.table.append(entry.key, entry.value)

    # Add an ACE to an ACL at a specified position.
    ##
    # position    ACE index in the ACL. If it's greater than ACL size, then it will be appended.
    # entry contains the key and value to be inserted.
    def do_insert(self, position, entry):
        if hasattr(self.table, 'insert'):
            self.table.insert(position, entry.key, entry.value)
        elif hasattr(self.table, 'push'):
            self.table.push(position, entry.key, entry.value)
        else:
            raise NotImplementedError

    # Update an ACE of an ACL at a specified position.
    ##
    # position    ACE index in the ACL.
    # entry contains the key and value to be set
    def do_set_entry(self, position, entry):
        self.table.set(position, entry.key, entry.value)

    # Erase an ACE at a specific location from the ACL.
    ##
    # position            The position of the ACE in the ACL.
    def do_erase(self, position):
        if hasattr(self.table, 'erase'):
            self.table.erase(position)
        elif hasattr(self.table, 'pop'):
            self.table.pop(position)
        else:
            raise NotImplementedError

    # Remove an LPTS entry at a specific location and also move all the following entries
    # up to fill the hole.
    ##
    # position            The position of the LPTS entry.
    # return              Entry from position.
    def do_pop(self, position):
        if hasattr(self.table, 'pop'):
            entry = self.table.pop(position)
        elif hasattr(self.table, 'get') and hasattr(self, 'erase'):
            entry = self.table.get(position)
            self.table.erase(position)
        else:
            raise NotImplementedError

        return entry

    def do_get_available_space(self):
        if hasattr(self.table, 'get_max_available_space'):
            return self.table.get_max_available_space()
        else:
            raise NotImplementedError

    # Delete all ACE's from the ACL.
    def do_clear(self):
        self.table.clear()

    # Retrieve an ACE from ACL's specific position.
    ##
    # position            The position of the ACE in the ACL.
    def do_get(self, position):
        descriptor = self.table.get(position)
        # descriptor, which is received here is either acl_entry_desc or lpts_entry_desc.
        # After ending of this function descriptor's underlying SWIG object will be destroyed with all it's data members.
        # Thereby, the descriptor should be saved.
        return table_entry.construct_from_descriptor(descriptor)

    # Attach the ACL to an entity.
    #
    # entity Attach the table to this entity. For example, a vrf, port etc.
    def attach(self, entity):
        if self.is_acl():
            entity.set_acl(self.table)

    # Attach the ACL to a default entity for this type of table.
    def attach_default(self):
        pass

    # Detach the ACL from a default entity for this type of table.
    def detach_default(self):
        pass

    # Check if table is ACL or not
    def is_acl(self):
        return isinstance(self.table, 'la_acl')
