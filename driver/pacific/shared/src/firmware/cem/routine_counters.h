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

#ifndef __CEM_ROUTINE_COUNTERS_H__
#define __CEM_ROUTINE_COUNTERS_H__

/// @file
/// @brief Counters to maintain the status of multi-cycle arc routines: Aging, Bulk Update and Load Balancing
///
/// Multi-cycle routines are processing one entry during main loop cycle. Therefore, these must keep track of the processed entry
/// and the routine stage.
///

// for uint / int typedefs
#include "common.h"
#include <inttypes.h>

//*********************************
// PERIODIC COUNTER
//*********************************

/// @brief Counter data that is kept per periodic command to capture the entry that is currently being handled
///
struct periodic_counter {
public:
    // Load balancing states
    enum state_e { VALID, DONE };

    // clang-format off
    union counter_data {
        struct bit_array {
            uint32_t em_entry   : EM_BITS_TO_REPRESENT_BANK_ENTRY;
            uint32_t em_bank    : EM_BITS_TO_REPRESENT_BANK;
            uint32_t for_cam    : 1;
            uint32_t em_core    : EM_BITS_TO_REPRESENT_CORE;
            uint32_t state      : 1;
        } FW_PACKED;
        bit_array bits;
        uint32_t count;
    };
    // clang-format on

    inline bool is_valid()
    {
        return data.bits.state != DONE;
    }

    inline void set_to_cam()
    {
        data.bits.for_cam = 1;
    }

    /// @brief counter initialization considering avaliable banks
    void init(uint32_t core);

    /// @brief Counter increase considering available banks. If all banks are iterated - switch to CAM
    /// The value of the counter is increased to the next legal value
    /// @return true        if counter is still valid
    ///         false       if counter is done
    bool incr();

    /// @brief Counter increase on cam entries that participate in evacuation for the initialized core.
    /// The value of the counter is increased to the next legal value
    /// assume for_cam = 1
    /// @return true        if counter is still valid
    ///         false       if counter is done - finished with all cam entries of the initialized core
    bool next_cam_entry();

public:
    counter_data data;

private:
    /// @brief Find next avaliable bank for a counter, including the current one. Does nothing if counter is set for CAM
    void next_allowed_bank();
};

//*********************************
// LOAD BALANCING
//*********************************

// clang-format off
/// @brief Load Balancing request will be submitted by CPU and contain the core to scan and the group to relocate.
/// CEM will identify the less congested core and relocate the group to it.
///
struct load_balance_request_data {

    uint32_t em_group       : 8;    ///< congested group - can be 0-255
    uint32_t em_core        : 4;    ///< congested core - can be 0-15
    uint32_t padding0       : 20;

} FW_PACKED;
// clang-format on

/// @brief Current state of load balancing request.
struct load_balance_data {

    enum stage_e { COPY, REMAP, DELETE, DONE };

    inline bool is_valid()
    {
        return stage != DONE;
    }

    /// @brief Initialization of the counter from a load balancing request data
    ///
    void init();

    /// @brief Increments counter between entries and stages.
    /// Considering allowed banks of the iterated core.
    /// If COPY stage is done, continues to DELETE.
    ///
    /// @return true    if increment operation succeded to find next valid value
    ///         false   if the counter is done
    ///
    bool incr();

public:
    // stage of the routine
    int stage;

    // counter of entries in the source core
    periodic_counter counter;

    // source core/group
    uint32_t em_core;
    uint32_t em_group;

    // destination
    uint32_t dest_core;
};

#endif // __CEM_ROUTINE_COUNTERS_H__
