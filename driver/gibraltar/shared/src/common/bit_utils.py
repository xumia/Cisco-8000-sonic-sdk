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


def get_all_1(num_of_bits):
    n = ((1 << num_of_bits) - 1)
    return n


def get_size_in_bits(n):
    if n > 0:
        size = 0
        my_n = n
        while (my_n > 0):
            size += 1
            my_n >>= 1
    else:
        size = 1
    return size


def get_bit(n, bit_index):
    bit = (n >> bit_index) & 0x1
    return bit


def set_bit(n, bit_index, data_to_set):
    new_n = set_bits(n, bit_index, bit_index, data_to_set)
    return new_n


def get_bits(n, msb, lsb):
    bit = (n >> lsb) & get_all_1(msb - lsb + 1)
    return bit


def set_bits(n, msb, lsb, data_to_set):
    data_to_set = data_to_set & get_all_1(msb - lsb + 1)
    new_n = n - (get_bits(n, msb, lsb) << lsb) + (data_to_set << lsb)
    return new_n


def bit_invert(n, size):
    mask = get_all_1(size)
    inverted_n = ~n & mask
    return inverted_n


def bit_reversal(x_in, size):
    x_out = 0
    for i in range(0, size):
        x_out = set_bit(x_out, size - 1 - i, get_bit(x_in, i))
    return x_out


def get_asserted_indexes(vector):
    n = get_size_in_bits(vector)
    for i in range(n):
        if (get_bits(vector, i, i) == 1):
            print("Asserted index = %0d" % (i))
