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

#include "hw_tables/lpm_types.h"

#ifndef __LEABA_LPM_READ_ENTRIES_H__
#define __LEABA_LPM_READ_ENTRIES_H__

#include <string>
#include <utility>

/// @file

namespace silicon_one
{

/// @brief Entry loading class.
///
/// Class functionality: read entries from a file written
/// in IPv4 format (a.b.c.d/e) into vector of keys and payloads.
class lpm_read_entries
{
public:
    /// @brief C'tor
    ///
    /// @param[in]  ipv4_and_ipv6       Randomally generate ipv4 and ipv6 entries or only ipv4.
    lpm_read_entries(bool ipv4_and_ipv6);

    /// @brief Read entries from a file to action vector.
    /// The file is zipped
    ///
    /// Entries are in a format:
    /// *> [vrf_id] ipv4_address1/length ipv4_address2
    ///
    /// where
    ///
    /// key = vrf_id + ipv4_address1
    /// length = number of MSB to consider in ipv4 address
    /// payload = ipv4_address2
    ///
    /// Examples
    /// *> 1.1.116.0/24 202.12.28.1
    /// or
    /// *> 1 10.31.26.0/24 12.123.70.226 0
    ///
    /// @param[in]      filename                Name of the file to load entries from.
    /// @param[in]      num_of_entries          Number of entries to read.
    ///
    /// @return vector of actions containing read entries.
    lpm_action_desc_vec_t read_entries(const std::string& filename, size_t num_of_entries) const;

    /// @brief Read entries from a file to action vector.
    /// The file is zipped
    ///
    /// Entries are in a format:
    /// lpm_insert key length payload
    /// lpm_modify key length payload
    /// lpm_remove key length
    ///
    /// where:
    /// key = hex number without leading 0x
    /// length = decimal number of total bits in the key starting LSB
    /// payload = hex number without leading 0x
    ///
    /// Example:
    /// lpm_insert 19fa3a244b24430a515053b9378ec2fb5dae 141 00123a
    ///
    /// @param[in]      filename                Name of the file to load entries from.
    /// @param[in]      num_of_entries          Number of entries to read.
    ///
    /// @return vector of actions containing read entries.
    lpm_action_desc_vec_t read_raw_entries(const std::string& filename, size_t num_of_entries, bool verbose) const;

    struct lpm_test_action_desc {
        bool is_update = false;
        bool is_rebalance = false;
        bool is_bulk_start = false;
        bool is_bulk_end = false;
        bool modify_if_exists = false;
        lpm_action_desc update_desc;
    };

    using lpm_test_action_desc_vec_t = vector_alloc<lpm_test_action_desc>;

    /// @brief Read entries from a file to action vector.
    /// The file is zipped
    ///
    /// Entries are in a format:
    /// lpm_insert key length payload
    /// lpm_modify key length payload
    /// lpm_remove key length
    /// lpm_rebalance
    /// lpm_bulk_start
    /// lpm_bulk_end
    ///
    /// where:
    /// key = hex number without leading 0x
    /// length = decimal number of total bits in the key starting LSB
    /// payload = hex number without leading 0x
    ///
    /// Example:
    /// lpm_insert 19fa3a244b24430a515053b9378ec2fb5dae 141 00123a
    ///
    /// @param[in]      filename                Name of the file to load entries from.
    /// @param[in]      num_of_entries          Number of entries to read.
    ///
    /// @return vector of actions containing read entries.
    lpm_test_action_desc_vec_t read_extended_raw_entries(const std::string& filename, size_t num_of_entries, bool verbose) const;

private:
    enum {
        BITS_IN_BYTE = 8,                                            ///< Number of bits in byte.
        BITS_IN_IPV4_ADDRESS = 32,                                   ///< Number of bits in IPv4 address.
        BYTES_IN_IPV4_ADDRESS = BITS_IN_IPV4_ADDRESS / BITS_IN_BYTE, ///< Number of bytes in IPv4 address.
        VRF_LENGTH = 11,                                             ///< VRF length.
        LPM_PAYLOAD_WIDTH = 20                                       ///< LPM payload width.
    };

    /// @brief Check if a string exists in a line.
    ///
    /// @param[in]      line            Line to search in.
    /// @param[in]      str             string to search.
    ///
    /// @return true if string exists, false otherwise.
    bool str_exists_in_line(const std::string& line, const std::string str) const;

    /// @brief Get minimal width of a prefix in multiplies of BITS_IN_BYTE.
    ///
    /// @param[in]      fields          Fields of prefix to calculate its width.
    ///
    /// @return Minimal width of prefix in multiples of BITS_IN_BYTE.
    size_t get_width(const uint8_t fields[BYTES_IN_IPV4_ADDRESS]) const;

    /// @brief Get key with given width, containing given prefix.
    ///
    /// @param[in]      fields          Fields of prefix to store in key.
    /// @param[in]      width           Given width of the key.
    /// @param[in]      vrf             VRF of the corresponding prefix (disregarded if equals -1).
    ///
    /// @return Key conatining the prefix.
    lpm_key_t get_key(const uint8_t fields[BYTES_IN_IPV4_ADDRESS], size_t width, int vrf) const;

    /// @brief Get payload containing given prefix with fixed IPv4 length width.
    ///
    /// @param[in]      fields          Fields of prefix to store in payload.
    ///
    /// @return Payload conatining the prefix.
    lpm_payload_t get_payload(const uint8_t fields[BYTES_IN_IPV4_ADDRESS]) const;

    /// @brief Read line.
    ///
    /// @param[in]      line            Line to read.
    /// @param[out]     key_fields      Fields to store key in.
    /// @param[out]     payload_fields  Fields to store payload in.
    /// @param[out]     width           Key width.
    /// @param[out]     vrf             VRF.
    void read_line(const std::string& line,
                   uint8_t key_fields[BYTES_IN_IPV4_ADDRESS],
                   uint8_t payload_fields[BYTES_IN_IPV4_ADDRESS],
                   uint8_t& width,
                   int& vrf) const;

    /// @brief Get key and payload from a line.
    ///
    /// @param[in]      line            Line to generate key from.
    ///
    /// @return pair of key and payload from a line.
    std::pair<lpm_key_t, lpm_payload_t> line_to_key_payload(const std::string& line) const;

    bool m_ipv4_and_ipv6; ///< Types of entries to generate.
};

} // namespace silicon_one

#endif
