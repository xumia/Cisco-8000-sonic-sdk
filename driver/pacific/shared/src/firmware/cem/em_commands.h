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

#ifndef __CEM_EM_COMMANDS_H__
#define __CEM_EM_COMMANDS_H__

/// @file
/// @brief CEM routines
///

#include "arc_cpu_common.h"
#include "common.h"
#include "inttypes.h"
#include "routine_counters.h"
#include "status_reg.h"

// clang-format off
/// @brief Intermediate data to maintain an entry during routine algorithms
///
struct em_entry_data {
    struct data_fields {
        int32_t orig_index           :EM_BITS_TO_REPRESENT_BANK_ENTRY + 1; ///< Original index of the key/payload. May be EM_NONE. Therefore we need additional bit
        int32_t orig_bank            :EM_BITS_TO_REPRESENT_BANK + 1;       ///< Original bank of the key/payload. May be EM_NONE. Therefore we need additional bit
        uint32_t orig_for_cam        :1;                                   ///< Whether entry was stored originally in cam
        uint32_t em_index            :EM_BITS_TO_REPRESENT_BANK_ENTRY;     ///< Entry in the bank. Not valid for CAM
        uint32_t em_bank             :EM_BITS_TO_REPRESENT_BANK;           ///< Bank to store the data. Valid only if record was found. Not relevant for CAM
        uint32_t age_value           :3;                                   ///< Age of the record
        uint32_t age_owner           :1;                                   ///< Whether record is sent by an owner device
        uint32_t age_valid           :1;                                   ///< Some EM commands do not return age.
        uint32_t key_size            :2;                                   ///< Key size encoding. 0, 1 - short keys. 2 - wide key (2 banks)
        uint32_t cores_bitmap        :NUM_EM_CORES;                        ///< A bitmap that indicates the cores we can insert the entry to.
    } FW_PACKED;

    long_entry_data rec;                        ///< Entry (long format)
    data_fields data;
};
// clang-format on

//************************
// ACTIVE BANKS
//************************

/// @brief EM active banks.
///
/// Central Exact Match is sharing banks between LPM and MAC data. On SDK loading, the setting is configured
/// and cannot be changed during the execution. The banks are set the same for all CEM cores.
/// The value is retrieved at the beginning and there is no need to request it again during the algorigthms.
extern uint32_t active_banks;

/// @brief This number used for determination of key size.
///
/// Since the HW is not returning the right size for keys on CAM, we use this number at read_request method
/// to get that size as a workaround.
extern uint32_t key_size_map;
//*************************
// COMMANDS
//*************************

/// @brief Submit Find Free Entry request to UAUX_EM_REQUEST_REG
///
/// The command submitted to EM cores or CAM
///     if found - returns the bank and the entry
///     if not found - returns one of the existing entries having the same hash key as the new candidate
///
/// @note Command works also if the key already found in EM. Don't use it in this case - use #lookup_request instead
/// @note Command does not return age/owner of the candidate.
///
/// Result of the command is stored in UAUX_EM_RESPONSE_REG:
///     em_bank -free bank to store record or bank of returned candidate
///     em_index -free index or index or returned candidate
///
/// @param[in]  bitset      banks to search for free entry
/// @param[in]  for_cam     search in CAM or banks - use insert_cam_entry for CAM insert
///
void ffe_request(em_entry_data* curr, uint32_t bitset, bool for_cam);

/// @brief Submits Lookup request to UAUX_EM_REQUEST_REG
/// Result:
///     em_bank         - bank of found key
///     em_index        - index of found key
///
/// @note Command does not return age/owner
///
void lookup_request(em_entry_data* curr);

/// @brief Submits read request to UAUX_EM_REQUEST_REG by core/bank/index/for_cam
///
/// @retval data is returned by the updated fields of #em_entry_data
void read_request(const periodic_counter* counter, em_entry_data* ret);

/// @brief Submit request to UAUX_GROUP_REQUEST_REG
/// Updates global context with the result
///
void group_request(const em_entry_data* curr);

/// @brief Submit Write/WriteAge request to UAUX_EM_REQUEST_REG
/// The result of the command is stored in UAUX_EM_RESPONSE_REG
/// The command submitted to cores or CAM
/// The entry is stored accoring to the new location (em_bank, em_entry)
///
/// @param[in]  cmd     can be either EM_COMMAND_WRITE or EM_COMMAND_AGE_WRITE
/// @param[in]  curr        entry to store
/// @param[in]  for_cam     store in CAM
///
void store_request(em_command_e cmd, const em_entry_data* curr, bool for_cam);

/// @brief Submit Delete request to UAUX_EM_REQUEST_REG
/// The result of the command is stored in UAUX_EM_RESPONSE_REG
/// The command submitted to cores or CAM
/// The entry is deleted according to the original location (orig_bank, orig_index)
/// and according to the core from group_data
///
/// @param[in]  curr        entry to delete
void delete_request(const em_entry_data* curr);

/// @brief Finds empty location to store the provided entry and if found - stores
///
/// @param[in]  curr        entry to find location for
/// @param[in]  bank_bitset banks to search location. If bit is off, bank is not seached
/// @param[in]  for_cam     whether to search in EM banks or in CAM
bool ffe_and_store(em_entry_data* curr, uint32_t bank_bitset, bool for_cam);

/// @brief Send request from the shadow copy of the reqister and poll on response status
///
/// @param[in]  shadow_reg      shadow of uaux register
/// @param[in]  reg             uaux register identifier
/// @param[in]  request_stat    status bit to submit the request
/// @param[in]  response_stat   status bit to poll on the response
///
/// @retval true if response was received. false if timeout occured
/// The result operation resides in uaux register. It's not copied to shadow register
///
bool request_and_poll(const void* shadow_reg, uaux_reg_name_e reg, uaux_reg_status_e request_stat, uaux_reg_status_e response_stat);

/// @brief Send request from the shadow copy of the reqister and poll on response status
///
/// @param[in]  location        EM entry's location data
/// @param[in]  rec             EM entry
/// @param[in]  for_cam         EM or TCAM entry to check
/// @param[in]  hit_expected    Check if the EM entry is expected to be present
///
/// @retval true if age value check succeeded
///
bool age_value_check(periodic_counter* location,
                     const em_entry_data* rec,
                     uint8_t for_cam,
                     bool hit_expected,
                     uint8_t expected_value);

#endif // __CEM_EM_COMMANDS_H__
