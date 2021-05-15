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

#ifndef __TAP_1149_H__
#define __TAP_1149_H__

#include "common/bit_vector.h"

#include <string>

namespace silicon_one
{
namespace tap1149
{

struct tms_tdi_pair {
    bool tms;
    bool tdi;
};

using tms_tdi_seq = vector_alloc<tms_tdi_pair>;

/// @brief Get sequence of TMS+TDI signals that will load the given IR into TAP.
///
/// @param[in] ir_length_bits   IR length in bits.
/// @param[in] ir               IR.
///
/// @return                     Vector of TMS+TDI pairs.
tms_tdi_seq get_tms_tdi_seq_set_ir(size_t ir_length_bits, const bit_vector& ir);

/// @brief Get sequence of TMS+TDI signals that will load the given DR into TAP.
///
/// @param[in] dr_length_bits   DR length in bits.
/// @param[in] dr               DR.
///
/// @return                     Vector of TMS+TDI pairs.
tms_tdi_seq get_tms_tdi_seq_set_dr(size_t dr_length_bits, const bit_vector& dr);

/// @brief Dump a vector of TMS+TDI pairs.
///
/// @param[in] seq  Vector of TMS+TDI pairs.
void dump_tms_tdi_seq(const tms_tdi_seq& seq);
}
}
#endif
