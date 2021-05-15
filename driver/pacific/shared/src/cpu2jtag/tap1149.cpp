// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "tap1149.h"
#include "common/logger.h"

#include <array>
#include <sstream>
#include <unordered_map>

using namespace std;

namespace silicon_one
{
namespace tap1149
{

// clang-format off
enum tap1149_state_e {
    TEST_LOGIC_RESET = 0,
    RUN_TEST_IDLE    = 1,
    SELECT_DR_SCAN   = 2,
    CAPTURE_DR       = 3,
    SHIFT_DR         = 4,
    EXIT_1_DR        = 5,
    PAUSE_DR         = 6,
    EXIT_2_DR        = 7,
    UPDATE_DR        = 8,
    SELECT_IR_SCAN   = 9,
    CAPTURE_IR       = 10,
    SHIFT_IR         = 11,
    EXIT_1_IR        = 12,
    PAUSE_IR         = 13,
    EXIT_2_IR        = 14,
    UPDATE_IR        = 15,
};

static inline tap1149_state_e
state_inc(tap1149_state_e state)
{
    return (tap1149_state_e)((int)state + 1);
}

// TAP state machine tansitions and resulting TMS:
//  current_state --> next_state_0 (tms==0)
//                --> next_state_1 (tms==1)
// clang-format off
static map<tap1149_state_e, std::array<tap1149_state_e, 2> > tap1149_state_transitions{
    // current_state      next_state_0   next_state_1
    {  TEST_LOGIC_RESET, { { RUN_TEST_IDLE, TEST_LOGIC_RESET } } },
    {  RUN_TEST_IDLE,    { { RUN_TEST_IDLE, SELECT_DR_SCAN } } },
    {  SELECT_DR_SCAN,   { { CAPTURE_DR,    SELECT_IR_SCAN } } },
    {  CAPTURE_DR,       { { SHIFT_DR,      EXIT_1_DR } } },
    {  SHIFT_DR,         { { SHIFT_DR,      EXIT_1_DR } } },
    {  EXIT_1_DR,        { { PAUSE_DR,      UPDATE_DR } } },
    {  PAUSE_DR,         { { PAUSE_DR,      EXIT_2_DR } } },
    {  EXIT_2_DR,        { { SHIFT_DR,      UPDATE_DR } } },
    {  UPDATE_DR,        { { RUN_TEST_IDLE, SELECT_DR_SCAN } } },
    {  SELECT_IR_SCAN,   { { CAPTURE_IR,    TEST_LOGIC_RESET } } },
    {  CAPTURE_IR,       { { SHIFT_IR,      EXIT_1_IR } } },
    {  SHIFT_IR,         { { SHIFT_IR,      EXIT_1_IR } } },
    {  EXIT_1_IR,        { { PAUSE_IR,      UPDATE_IR } } },
    {  PAUSE_IR,         { { PAUSE_IR,      EXIT_2_IR } } },
    {  EXIT_2_IR,        { { SHIFT_IR,      UPDATE_IR } } },
    {  UPDATE_IR,        { { RUN_TEST_IDLE, SELECT_IR_SCAN } } },
};
// clang-format on

static inline bool
is_ir_state(tap1149_state_e state)
{
    return (state >= tap1149_state_e::SELECT_IR_SCAN && state <= tap1149_state_e::UPDATE_IR);
}

static inline bool
is_dr_state(tap1149_state_e state)
{
    return (state >= tap1149_state_e::SELECT_DR_SCAN && state <= tap1149_state_e::UPDATE_DR);
}

static int
get_state_transition_tms(tap1149_state_e curr_state, tap1149_state_e next_state)
{
    if (tap1149_state_transitions[curr_state][0] == next_state) {
        return 0;
    }
    if (tap1149_state_transitions[curr_state][1] == next_state) {
        return 1;
    }

    return -1;
}

static void get_tms_seq_state_transition_2(vector<bool>& tms_seq, tap1149_state_e curr_state, tap1149_state_e next_state);

static void
get_tms_seq_state_transition_3(vector<bool>& tms_seq,
                               tap1149_state_e curr_state,
                               tap1149_state_e next_state,
                               tap1149_state_e trans_state)
{
    if (curr_state != trans_state) {
        get_tms_seq_state_transition_2(tms_seq, curr_state, trans_state);
    }
    if (trans_state != next_state) {
        get_tms_seq_state_transition_2(tms_seq, trans_state, next_state);
    }
}

static void
get_tms_seq_state_transition_2(vector<bool>& tms_seq, tap1149_state_e curr_state, tap1149_state_e next_state)
{
    // single-state transitions
    int state_transition_tms = get_state_transition_tms(curr_state, next_state);
    if (state_transition_tms >= 0) {
        tms_seq.push_back((bool)state_transition_tms);
    }
    // multi-state transitions
    else if (is_dr_state(curr_state) && is_dr_state(next_state) && next_state > curr_state) {
        if (curr_state == tap1149_state_e::CAPTURE_DR && next_state != tap1149_state_e::SHIFT_DR) {
            get_tms_seq_state_transition_3(tms_seq, curr_state, next_state, tap1149_state_e::EXIT_1_DR);
        } else {
            get_tms_seq_state_transition_3(tms_seq, curr_state, next_state, state_inc(curr_state));
        }
    } else if (is_ir_state(curr_state) && is_ir_state(next_state) && next_state > curr_state) {
        if (curr_state == tap1149_state_e::CAPTURE_IR && next_state != tap1149_state_e::SHIFT_IR) {
            get_tms_seq_state_transition_3(tms_seq, curr_state, next_state, tap1149_state_e::EXIT_1_IR);
        } else {
            get_tms_seq_state_transition_3(tms_seq, curr_state, next_state, state_inc(curr_state));
        }
    } else if (curr_state < tap1149_state_e::SELECT_DR_SCAN) {
        get_tms_seq_state_transition_3(tms_seq, curr_state, next_state, state_inc(curr_state));
    } else if (curr_state == tap1149_state_e::SELECT_DR_SCAN && is_ir_state(next_state)) {
        get_tms_seq_state_transition_3(tms_seq, curr_state, next_state, tap1149_state_e::SELECT_IR_SCAN);
    } else if (next_state == tap1149_state_e::RUN_TEST_IDLE) {
        if (is_ir_state(curr_state)) {
            get_tms_seq_state_transition_3(tms_seq, curr_state, next_state, tap1149_state_e::UPDATE_IR);
        } else {
            get_tms_seq_state_transition_3(tms_seq, curr_state, next_state, tap1149_state_e::UPDATE_DR);
        }
    } else {
        log_err(CPU2JTAG, "unknown state transition in set_state: from %d to %d", (int)curr_state, (int)next_state);
    }
}

tap1149::tms_tdi_seq
get_tms_tdi_seq_set_ir(size_t ir_width_bits, const bit_vector& ir)
{
    tap1149::tms_tdi_seq tms_tdi_seq; // returned seq

    // get TMS transitions for reaching from RUN_TEST_IDLE to SHIFT_IR
    vector<bool> tms_seq_to_shift_ir;
    get_tms_seq_state_transition_2(tms_seq_to_shift_ir, tap1149_state_e::RUN_TEST_IDLE, tap1149_state_e::SHIFT_IR);

    // add TMS transitions to returned seq
    for (size_t i = 0; i < tms_seq_to_shift_ir.size(); ++i) {
        tms_tdi_seq.push_back({.tms = tms_seq_to_shift_ir[i], .tdi = 0});
    }

    // get TMS value for staying in SHIFT_IR (sequence of length 1)
    vector<bool> tms_seq_stay_in_shift_ir;
    get_tms_seq_state_transition_2(tms_seq_stay_in_shift_ir, tap1149_state_e::SHIFT_IR, tap1149_state_e::SHIFT_IR);

    // add TDI values to returned seq
    for (size_t i = 0; i < ir_width_bits - 1; ++i) {
        bool tdi = ir.bit(i);
        tms_tdi_seq.push_back({.tms = tms_seq_stay_in_shift_ir[0], tdi});
    }

    // get TMS transitions for reaching from SHIFT_IR to RUN_TEST_IDLE
    vector<bool> tms_seq_to_run_test_idle;
    get_tms_seq_state_transition_2(tms_seq_to_run_test_idle, tap1149_state_e::SHIFT_IR, tap1149_state_e::RUN_TEST_IDLE);
    // add TMS transitions to returned seq
    for (size_t i = 0; i < tms_seq_to_run_test_idle.size(); ++i) {
        bool tdi = (i == 0 ? ir.bit(ir_width_bits - 1) : 0 /* dummy data */);

        tms_tdi_seq.push_back({.tms = tms_seq_to_run_test_idle[i], .tdi = tdi});
    }

    return tms_tdi_seq;
}

tap1149::tms_tdi_seq
get_tms_tdi_seq_set_dr(size_t dr_width_bits, const bit_vector& dr)
{
    tap1149::tms_tdi_seq tms_tdi_seq; // returned seq

    // get TMS transitions for reaching from RUN_TEST_IDLE to SHIFT_DR
    vector<bool> tms_seq_to_shift_dr;
    get_tms_seq_state_transition_2(tms_seq_to_shift_dr, tap1149_state_e::RUN_TEST_IDLE, tap1149_state_e::SHIFT_DR);

    // add TMS transitions to returned seq
    for (size_t i = 0; i < tms_seq_to_shift_dr.size(); ++i) {
        tms_tdi_seq.push_back({tms_seq_to_shift_dr[i], 0});
    }

    // get TMS value for staying in SHIFT_DR
    vector<bool> tms_seq_stay_in_shift_dr;
    get_tms_seq_state_transition_2(tms_seq_stay_in_shift_dr, tap1149_state_e::SHIFT_DR, tap1149_state_e::SHIFT_DR);

    // add TDI values to returned seq
    tms_tdi_seq.push_back({tms_seq_stay_in_shift_dr[0], 0}); // dummy data
    for (size_t i = 0; i < dr_width_bits - 1; ++i) {
        tms_tdi_seq.push_back({.tms = tms_seq_stay_in_shift_dr[0], .tdi = dr.bit(i)});
    }

    // get TMS transitions for reaching from SHIFT_DR to RUN_TEST_IDLE
    vector<bool> tms_seq_to_run_test_idle;
    get_tms_seq_state_transition_2(tms_seq_to_run_test_idle, tap1149_state_e::SHIFT_DR, tap1149_state_e::RUN_TEST_IDLE);

    // add TMS transitions to returned seq
    for (size_t i = 0; i < tms_seq_to_run_test_idle.size(); ++i) {
        bool tdi = (i == 0 ? dr.bit(dr_width_bits - 1) : 0 /* dummy data */);

        tms_tdi_seq.push_back({.tms = tms_seq_to_run_test_idle[i], .tdi = tdi});
    }

    return tms_tdi_seq;
}

void
dump_tms_tdi_seq(const tms_tdi_seq& seq)
{
    // The sequence of tms-tdi pairs can be a few thousands entries long.
    // Print up to 10 pairs per row:

    stringstream ss;
    log_xdebug(CPU2JTAG, "%s: start", __func__);
    for (size_t i = 0, j = 0; i < seq.size(); ++i) {
        ss << " (" << seq[i].tms << ", " << seq[i].tdi << "),";
        if (i % 10 == 9) {
            log_xdebug(CPU2JTAG, "%s: from %ld to %ld, %s", __func__, j, i, ss.str().c_str());
            ss.str("");
            j = i + 1;
        }
    }
    log_xdebug(CPU2JTAG, "%s: end", __func__);
}

} // namespace tap1149
} // namespace silicon_one
