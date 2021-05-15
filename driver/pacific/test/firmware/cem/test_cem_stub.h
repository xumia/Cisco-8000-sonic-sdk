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

#ifndef __TEST_CEM_TEST_CEM_STUB_H__
#define __TEST_CEM_TEST_CEM_STUB_H__

/// @file
/// @brief Testing stubs
///

#include "arc_cpu_common.h"
#include "common.h"
#include "counters.h"
#include "uaux_regs.h"

/// @brief Dimensions of CEM_hash
/// Defailt values are 1x2x3 (CORESxBANKSxENTRIES)
/// Each test can modify them, but make sure you don't exceed MAX_VALUE = CEM_NUM_IDXS in total
extern int test_CEM_NUM_CORES;
extern int test_CEM_NUM_BANKS;
extern int test_CEM_NUM_ENTRIES;

/// @brief group <--> core mapping
/// Defailt value: 0 to all
/// Each test can modify them to send different groups to different cores
extern int test_group2core[10];

/// @brief Requests from CEM that will be submitted to the main loop
/// @details The pointer will be initialized during the test
typedef void (*test_main_loop_poll_func_ptr)();
extern test_main_loop_poll_func_ptr test_main_loop_poll_callback;

/// @brief data is kept in the hash in this format
typedef em_response_data cem_data;

/// @brief Updates test_exit_status and exits to debugger shell
///
void test_exit(int status);

//*********************************
// Accessors to CEM hash
//*********************************

/// @brief Initialyzes CEM data structures
void test_init_cem();

/// @brief Returns pointer to the entry
cem_data* test_get_cem(uint32_t core, uint32_t bank, uint32_t entry);

/// @brief Returns the 4 bytes of the payload at  <entry> stored in <bank>
uint32_t test_get_cem_payload(uint32_t core, uint32_t bank, uint32_t entry);

/// @brief Returns the 4 bytes of the payload at  <entry> stored in <bank>
uint32_t test_get_cem_age(uint32_t core, uint32_t bank, uint32_t entry);

/// @brief Prints content of CEM entry
void test_print_cem(uint32_t core, uint32_t bank, uint32_t entry);

/// @brief Gets counter value
uint32_t test_get_counter(counters::type_e type, counters::occupancy_id::type_e occ_type, uint32_t id);

/// @brief Prints counter
void test_print_counter(counters::type_e type, counters::occupancy_id::type_e occ_type, uint32_t id);

/// @brief Checks counter and asserts if does not match expected
void test_check_counter(counters::type_e type, counters::occupancy_id::type_e occ_type, uint32_t id, uint32_t exp_val);

//*********************************
// Command generators
// hash_key = (key[0] + key[1] * bank) % num_of_banks
// group = key[3]
//*********************************

/// @brief Create learning request command for testing
///
/// @param[in]  cmd         ADD_NEW, UPDATE or REFRESH
/// @param[in]  key         first 4 bytes of key
/// @param[in]  payload     first 4 bytes of payload
/// We don't need more than 4 bytes for testing
///
void test_create_learn_cmd(learn_command_e cmd, uint32_t key, uint32_t payload, bool owner);

/// @brief Create cpu request for testing
///
/// @param[in]  cmd         ARC_CPU command struct, includes command type, key and payload
///
void test_create_cpu_cmd(arc_cpu_command* reg);

/// @brief Create entry in rule table
///
/// @param[in]  cmd         UPDATE, DELETE or SEND_TO_CPU
/// @param[in]  key         first 4 bytes of key
/// @param[in]  payload     first 4 bytes of payload
/// We don't need more than 4 bytes for testing
///
void test_create_rule(bulk_command_e cmd, uint32_t key, uint32_t payload);

/// @brief Submit Load Balancing request data
///
/// @param[in]  core        congested core
/// @param[in]  group       group to relocate
///
void test_create_load_balance_request(uint32_t core, uint32_t group);

#endif // __TEST_CEM_TEST_CEM_STUB_H__
