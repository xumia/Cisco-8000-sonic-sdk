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

#ifndef __CEM_ARC_ROUTINES_H__
#define __CEM_ARC_ROUTINES_H__

#include <stdint.h>

/// @file
/// @brief ARC high level algorithms to handle CEM routines
///

/// @brief Initialize all occupancy counters, both for the group counter, and for the core counters
void initialize_occupancy_counters();

/// @brief Initialize active banks
void initialize_active_banks();

/// @brief Execute Learning command (LEARN_COMMAND_NEW_WRITE, LEARN_COMMAND_UPDATE or LEARN_COMMAND_REFRESH)
/// LEARN_COMMAND_NEW_WRITE     - adding new entry to EM. Happens when HW encountered new SA/port
/// LEARN_COMMAND_UPDATE        - updating payload of existing entry. Happens when the entry existed, but the port had changed
/// LEARN_COMMAND_REFRESH       - refreshing the age of existing entry. Happens when an existing entry was accessed.
/// This routine is invoked when a learn event is received in UAUX_STATUS_REG.
/// The data and the command are received in UAUX_LEARN_REG register.
///
void em_learn_routine();

/// @brief Initialize aging routine.
/// Aging routine is initialized once in a defined interval.
void init_aging_routine();

/// @brief Execute Aging routine on one entry, as a part of periodic age update.
/// The routine maintains an iterator for all cores/entries and perform query on one entry (banks and CAM) each iteration.
/// Once done, it will turn off UAUX_REG_STATUS_AGE bit in status register.
///
void aging_routine();

/// @brief If there are entries with chance for succesful evacuation, this method will try to evacuate one of those entries,
/// using evacuation_routine().
///
void evacuate_if_need();

/// @brief Execute cpu command routine on one entry, as a part of cpu command.
/// The command can be one of the following: SET_MAX_MAC, INIT_MAX_MAC,ARC_CPU_COMMAND_SET_ACTIVE_REDUCED_BANKS,
/// ARC_CPU_COMMAND_SET_ACTIVE_FULL_BANKS,
/// ARC_CPU_COMMAND_INSERT_TABLE_SINGLE_ENTRY, ARC_CPU_COMMAND_ERASE_TABLE_SINGLE_ENTRY.
/// For insert operation, if load balancing is ongoing, lookup command may be unavailibe untill load balancing is finished.
/// Once done, it will turn off UAUX_REG_STATUS_CPU_CMD bit in status register.
///
void cpu_cmd_routine();

/// @brief Execute Bulk Update routine on one entry, as a part of periodic bulk update.
/// The update can be one of the following: BULK_COMMAND_UPDATE, BULK_COMMAND_DELETE, BULK_COMMAND_SEND_TO_CPU.
/// The routine maintains an iterator for all cores/entries and perform query on one entry (banks and CAM) each iteration.
/// Once done, it will turn off UAUX_REG_STATUS_BULK bit in status register.
///
void bulk_update_routine();

/// @brief Execute Load balancing routine on one entry.
/// CEM is reported a group with high access rate or core with high occupancy. The group should be transferred to a less congested
/// core.
/// The destination core is selected based on occupancy counters.
/// The operation consists of two states: COPY to destination and DELETE from sources. After COPY, the mapping between group and
/// core
/// can be updated.
///
/// Given a core and a group, the routine maintains an iterator for core's entries and perform one operation (copy to other core or
/// delete from old core).
/// Once done, it will turn off UAUX_REG_STATUS_LOAD_BALANCE bit in status register.
///
void load_balance_routine();

/// @brief Configure ARC aging timer related parameters
/// Through this function aging timer interval and aging can be configured, enabled or disabled.
///
/// @param[in]  interval                AGE_INTERVAL_DISABLED or 0 to disable ARC aging_time
///                                     Non-zero to run age scrubbing in 100ms units.
///
void configure_aging_params(uint32_t interval);

struct arc_cpu_feature_type_value;
extern arc_cpu_feature_type_value feature_tlvs[];

extern uint16_t sram_per_core_utilization[];
extern uint8_t cam_per_core_utilization[];

#endif // __CEM_ARC_ROUTINES_H__
