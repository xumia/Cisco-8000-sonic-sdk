// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
//
// This file and all technical concepts, proprietary knowledge, algorithms and
// intellectual property rights it contains (collectively the "Confidential Information"),
// are the sole propriety information of Cisco and shall remain at Cisco's ownership.
// You shall not disclose the Confidential Information to any third party and you
// shall use it solely in connection with operating and/or maintaining of Cisco's
// products and pursuant to the terms and conditions of the license agreement you
// entered into with Cisco.
//
// THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
// IN NO EVENT SHALL CISCO BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
// AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
// THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// END_LEGAL

#include "test_lpm_read_entries.h"
#include "lpm/lpm_common.h"

#include <fstream>

#include <boost/iostreams/copy.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/iostreams/filtering_stream.hpp>
#include <iostream>
#include <stdlib.h>

#include <regex>

namespace silicon_one
{

using smatch_alloc
    = std::match_results<std::string::const_iterator, allocator_wrapper<std::sub_match<std::string::const_iterator> > >;

lpm_read_entries::lpm_read_entries(bool ipv4_and_ipv6) : m_ipv4_and_ipv6(ipv4_and_ipv6)
{
}

size_t
lpm_read_entries::get_width(const uint8_t fields[BYTES_IN_IPV4_ADDRESS]) const
{
    for (size_t i = 0; i < BYTES_IN_IPV4_ADDRESS; i++) {
        if (fields[BYTES_IN_IPV4_ADDRESS - 1 - i] != 0) {
            return BITS_IN_IPV4_ADDRESS - i * BITS_IN_BYTE;
        }
    }

    return 0;
}

lpm_key_t
lpm_read_entries::get_key(const uint8_t fields[BYTES_IN_IPV4_ADDRESS], size_t width, int vrf) const
{
    // table type + vrf + ipv4
    size_t max_key_width = VRF_LENGTH + BITS_IN_IPV4_ADDRESS + 1;
    lpm_key_t key(0 /*value*/, max_key_width);

    bool entry_type = (m_ipv4_and_ipv6) ? (rand() % 2) : 0;
    key.set_bit(max_key_width - 1, entry_type);

    key.set_bits_from_msb(1, VRF_LENGTH, vrf);

    for (size_t idx = 0; idx < BYTES_IN_IPV4_ADDRESS; ++idx) {
        size_t offset = VRF_LENGTH + 1 + idx * BITS_IN_BYTE;
        key.set_bits_from_msb(offset, BITS_IN_BYTE, fields[idx]);
    }

    key = key >> (BITS_IN_IPV4_ADDRESS - width);

    return key;
}

lpm_payload_t
lpm_read_entries::get_payload(const uint8_t fields[BYTES_IN_IPV4_ADDRESS]) const
{
    uint64_t address = 0;
    for (size_t i = 0; i < BYTES_IN_IPV4_ADDRESS; i++) {
        address <<= BITS_IN_BYTE;
        address |= fields[i];
    }

    return address;
}

std::pair<lpm_key_t, lpm_payload_t>
lpm_read_entries::line_to_key_payload(const std::string& line) const
{
    uint8_t key_fields[BYTES_IN_IPV4_ADDRESS] = {0};
    uint8_t payload_fields[BYTES_IN_IPV4_ADDRESS] = {0};
    uint8_t width = 0;
    int vrf = 0;

    read_line(line, key_fields, payload_fields, width, vrf);

    lpm_key_t key = get_key(key_fields, width, vrf);
    lpm_payload_t payload = get_payload(payload_fields);

    return std::make_pair(key, payload);
}

void
lpm_read_entries::read_line(const std::string& line,
                            uint8_t key_fields[BYTES_IN_IPV4_ADDRESS],
                            uint8_t payload_fields[BYTES_IN_IPV4_ADDRESS],
                            uint8_t& width,
                            int& vrf) const
{
    uint8_t first_digit_index = line.find_first_of("0123456789");
    if (line.find('.', first_digit_index) < line.find(' ', first_digit_index)) {
        // Prefix start immediately: No VRF.
        if (str_exists_in_line(line, "/")) {
            sscanf(line.c_str(),
                   "*> %hhu.%hhu.%hhu.%hhu/%hhu %hhu.%hhu.%hhu.%hhu",
                   &key_fields[0],
                   &key_fields[1],
                   &key_fields[2],
                   &key_fields[3],
                   &width,
                   &payload_fields[0],
                   &payload_fields[1],
                   &payload_fields[2],
                   &payload_fields[3]);
        } else {
            sscanf(line.c_str(),
                   "*> %hhu.%hhu.%hhu.%hhu %hhu.%hhu.%hhu.%hhu",
                   &key_fields[0],
                   &key_fields[1],
                   &key_fields[2],
                   &key_fields[3],
                   &payload_fields[0],
                   &payload_fields[1],
                   &payload_fields[2],
                   &payload_fields[3]);
            width = get_width(key_fields);
        }
    } else {
        // A number before prefix: VRF.
        if (str_exists_in_line(line, "/")) {
            sscanf(line.c_str(),
                   "*> %d %hhu.%hhu.%hhu.%hhu/%hhu %hhu.%hhu.%hhu.%hhu",
                   &vrf,
                   &key_fields[0],
                   &key_fields[1],
                   &key_fields[2],
                   &key_fields[3],
                   &width,
                   &payload_fields[0],
                   &payload_fields[1],
                   &payload_fields[2],
                   &payload_fields[3]);
        } else {
            sscanf(line.c_str(),
                   "*> %d %hhu.%hhu.%hhu.%hhu %hhu.%hhu.%hhu.%hhu",
                   &vrf,
                   &key_fields[0],
                   &key_fields[1],
                   &key_fields[2],
                   &key_fields[3],
                   &payload_fields[0],
                   &payload_fields[1],
                   &payload_fields[2],
                   &payload_fields[3]);
            width = get_width(key_fields);
        }
    }
}

bool
lpm_read_entries::str_exists_in_line(const std::string& line, const std::string str) const
{
    return line.find(str) != std::string::npos;
}

lpm_action_desc_vec_t
lpm_read_entries::read_entries(const std::string& filename, size_t num_of_entries) const
{
    lpm_action_desc_vec_t actions;

    // Unzipping
    std::string base_dir("shared/");
    std::string full_filename = base_dir + filename;

    std::ifstream bf(full_filename.c_str(), std::ios_base::in | std::ios_base::binary);
    boost::iostreams::filtering_stream<boost::iostreams::input> f;
    f.push(boost::iostreams::gzip_decompressor());
    f.push(bf);

    std::string line;

    while (getline(f, line) && actions.size() < num_of_entries) {
        if (!str_exists_in_line(line, "*> ")) {
            continue;
        }

        const std::pair<lpm_key_t, lpm_payload_t> key_payload(line_to_key_payload(line));
        const lpm_key_t& key = key_payload.first;

        actions.push_back(lpm_action_desc(lpm_action_e::INSERT, key, key_payload.second));
    }

    return actions;
}

lpm_read_entries::lpm_test_action_desc_vec_t
lpm_read_entries::read_extended_raw_entries(const std::string& filename, size_t num_of_entries, bool verbose) const
{
    lpm_test_action_desc_vec_t actions;

    // Unzipping
    std::string base_dir("shared/");
    std::string full_filename = base_dir + filename;

    std::ifstream bf(full_filename.c_str(), std::ios_base::in | std::ios_base::binary);
    boost::iostreams::filtering_stream<boost::iostreams::input> f;
    f.push(boost::iostreams::gzip_decompressor());
    f.push(bf);

    static std::regex line_insert_regex("^((lpm_insert)|(lpm_insert_or_modify))* ([a-fA-F0-9]+) ([0-9]+) ([a-fA-F0-9]+)");
    static std::regex line_remove_regex("^lpm_remove ([a-fA-F0-9]+) ([0-9]+)");
    static std::regex line_modify_regex("^lpm_modify ([a-fA-F0-9]+) ([0-9]+) ([a-fA-F0-9]+)");
    static std::regex line_bulk_start_regex("^lpm_bulk_start");
    static std::regex line_bulk_end_regex("^lpm_bulk_end");
    static std::regex line_rebalance_regex("^lpm_rebalance");

    std::string line;
    while (getline(f, line) && actions.size() < num_of_entries) {
        smatch_alloc line_match;
        if (std::regex_search(line, line_match, line_insert_regex)) {

            bool modify_if_exists = (line_match[1] == std::string("lpm_insert_or_modify"));
            std::string key_str = line_match[4];
            size_t length = stoi(line_match[5]);
            size_t payload = stoi(line_match[6], nullptr, 16);

            if (verbose) {
                printf("%s: INSERT %s %lu %lu\n", __func__, key_str.c_str(), length, payload);
            }

            lpm_key_t key(key_str, length);

            lpm_test_action_desc test_action;
            test_action.is_update = true;
            test_action.modify_if_exists = modify_if_exists;
            test_action.update_desc = lpm_action_desc(lpm_action_e::INSERT, key, payload);
            actions.push_back(test_action);
        } else if (std::regex_search(line, line_match, line_remove_regex)) {

            std::string key_str = line_match[1];
            size_t length = stoi(line_match[2]);

            if (verbose) {
                printf("%s: REMOVE %s %lu\n", __func__, key_str.c_str(), length);
            }

            lpm_key_t key(key_str, length);

            lpm_test_action_desc test_action;
            test_action.is_update = true;
            test_action.update_desc = lpm_action_desc(lpm_action_e::REMOVE, key, INVALID_PAYLOAD);
            actions.push_back(test_action);
        } else if (std::regex_search(line, line_match, line_modify_regex)) {

            std::string key_str = line_match[1];
            size_t length = stoi(line_match[2]);
            size_t payload = stoi(line_match[3], nullptr, 16);

            if (verbose) {
                printf("%s: MODIFY %s %lu %lu\n", __func__, key_str.c_str(), length, payload);
            }

            lpm_key_t key(key_str, length);

            lpm_test_action_desc test_action;
            test_action.is_update = true;
            test_action.update_desc = lpm_action_desc(lpm_action_e::MODIFY, key, payload);
            actions.push_back(test_action);
        } else if (std::regex_search(line, line_match, line_bulk_start_regex)) {
            if (verbose) {
                printf("%s: BULK START\n", __func__);
            }

            lpm_test_action_desc test_action;
            test_action.is_bulk_start = true;
            actions.push_back(test_action);
        } else if (std::regex_search(line, line_match, line_bulk_end_regex)) {
            if (verbose) {
                printf("%s: BULK END\n", __func__);
            }

            lpm_test_action_desc test_action;
            test_action.is_bulk_end = true;
            actions.push_back(test_action);
        } else if (std::regex_search(line, line_match, line_rebalance_regex)) {
            if (verbose) {
                printf("%s: rebalance\n", __func__);
            }

            lpm_test_action_desc test_action;
            test_action.is_rebalance = true;
            actions.push_back(test_action);
        }
    }

    return actions;
}

lpm_action_desc_vec_t
lpm_read_entries::read_raw_entries(const std::string& filename, size_t num_of_entries, bool verbose) const
{
    lpm_test_action_desc_vec_t test_actions = read_extended_raw_entries(filename, num_of_entries, verbose);
    lpm_action_desc_vec_t actions;
    for (const auto& action : test_actions) {
        dassert_crit(action.is_update);
        actions.push_back(action.update_desc);
    }
    return actions;
}

} // namespace silicon_one
