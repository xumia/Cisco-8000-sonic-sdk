#!/usr/bin/env python3
# BEGIN_LEGAL
#
# Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

import hw_tablescli
import random

NUM_OF_BANKS = 4
NUM_OF_BANK_ENTRIES = 4096
NUM_OF_CAM_ENTRIES = 32
MOVING_DEPTH = 3


def create_em(num_of_banks, num_of_bank_entries, num_of_cam_entries, entry_width, key_widths):
    """
    Creates a physical_em with the given parameters
    :param num_of_banks: The number of banks
    :param num_of_bank_entries: The number of bank entries
    :param num_of_cam_entries:  The number of CAM entries
    :param entry_width: The width of each entry
    :param key_widths: A list of possible key widths
    :return: The physical_em
    """
    em = hw_tablescli.physical_em()

    # Puts in the key widths
    assert key_widths != []
    em.key_widths = hw_tablescli.size_t_vector()
    for key_width in key_widths:
        em.key_widths.push_back(key_width)

    # Updates the parameters
    em.banks.resize(num_of_banks)
    em.bank_size = num_of_bank_entries
    em.cam_size = num_of_cam_entries
    em.data_width = entry_width

    # Generates (pseudo) RC5 for each bank
    primary_key = key_widths[0]
    for i in range(num_of_banks):
        em.banks[i].rc5 = hw_tablescli.generate_pseudo_rc5(primary_key, i)
        em.banks[i].is_active = True
    return em


def create_em_payload(value, width):
    return hw_tablescli.em_payload(hex(value)[2:], width)


def create_em_key(value, width):
    return hw_tablescli.em_key(hex(value)[2:], width)


class random_em_generator():
    """
    A class that generates random rm keys/payloads with using a given seed to generate the random values.
    """

    def __init__(self, seed):
        self.seed = seed
        self.random_object = random.Random(seed)

    def random_em_payload(self, width):
        return create_em_payload(self.random_object.getrandbits(width), width)

    def random_em_key(self, width):
        return create_em_key(self.random_object.getrandbits(width), width)
