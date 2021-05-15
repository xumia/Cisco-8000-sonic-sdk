// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "ctm_common.h"
#include "ctm_config_tcam.h"
namespace silicon_one
{

using namespace ctm;

// clang-format off
// map between key channel to slice ifs
const std::array<std::array<ctm::slice_interface_input_desc, ctm::NUM_CHANNELS_PER_CORE>,  ctm::NUM_RINGS> ctm_config_tcam::s_ctm_slice_ifs_mapping_stand_alone_in = {{
      //  key channel 0,        key channel 1,       key channel 2,       key channel 3,        key channel 4
       {{ {0, INTERFACE_INVAL}, {0, INTERFACE_FWD0}, {0, INTERFACE_FWD1}, {0, INTERFACE_TX0},   {0, INTERFACE_TX1} } },   // core_idx = 0 - slice 0 FW + TX
       {{ {0, INTERFACE_INVAL}, {1, INTERFACE_FWD0}, {1, INTERFACE_FWD1}, {1, INTERFACE_TX0},   {1, INTERFACE_TX1} } },   // core_idx = 1 - slice 1 FW + TX
       {{ {0, INTERFACE_INVAL}, {2, INTERFACE_FWD0}, {2, INTERFACE_FWD1}, {2, INTERFACE_TX0},   {2, INTERFACE_TX1} } },   // core_idx = 2 - slice 2 FW + TX
       {{ {0, INTERFACE_INVAL}, {3, INTERFACE_FWD0}, {3, INTERFACE_FWD1}, {3, INTERFACE_TX0},   {3, INTERFACE_TX1} } },   // core_idx = 3 - slice 3 FW + TX
       {{ {0, INTERFACE_INVAL}, {4, INTERFACE_FWD0}, {4, INTERFACE_FWD1}, {4, INTERFACE_TX0},   {4, INTERFACE_TX1} } },   // core_idx = 4 - slice 4 FW + TX
       {{ {0, INTERFACE_INVAL}, {5, INTERFACE_FWD0}, {5, INTERFACE_FWD1}, {5, INTERFACE_TX0},   {5, INTERFACE_TX1} } },   // core_idx = 5 - slice 5 FW + TX
       {{ {0, INTERFACE_TERM},  {1, INTERFACE_TERM}, {2, INTERFACE_TERM}, {0, INTERFACE_INVAL}, {0, INTERFACE_INVAL} } }, // core_idx = 6 - Term - slice 0,1,2
       {{ {3, INTERFACE_TERM},  {4, INTERFACE_TERM}, {5, INTERFACE_TERM}, {0, INTERFACE_INVAL}, {0, INTERFACE_INVAL} } } // core_idx = 7 - Term - slice 3,4,5
}};

const std::array<std::array<ctm::slice_interface_input_desc, ctm::NUM_CHANNELS_PER_CORE>, ctm::NUM_RINGS> ctm_config_tcam::s_ctm_slice_ifs_mapping_line_card_in = {{
      //  key channel 0,        key channel 1,       key channel 2,       key channel 3,        key channel 4
       { { {0, INTERFACE_FWD0}, {0, INTERFACE_FWD1}, {0, INTERFACE_INVAL}, {0, INTERFACE_INVAL}, {0, INTERFACE_INVAL} } },   // core_idx = 0 - slice 0 FW
       { { {0, INTERFACE_FWD0}, {0, INTERFACE_FWD1}, {0, INTERFACE_TX0},   {0, INTERFACE_TX1},   {0, INTERFACE_INVAL} } },   // core_idx = 1 - slice 0 FW and TX
       { { {1, INTERFACE_FWD0}, {1, INTERFACE_FWD1}, {0, INTERFACE_INVAL}, {0, INTERFACE_INVAL}, {0, INTERFACE_INVAL} } },   // core_idx = 2 - slice 1 FW
       { { {1, INTERFACE_FWD0}, {1, INTERFACE_FWD1}, {1, INTERFACE_TX0},   {1, INTERFACE_TX1},   {0, INTERFACE_INVAL} } },   // core_idx = 3 - slice 1 FW and TX
       { { {2, INTERFACE_FWD0}, {2, INTERFACE_FWD1}, {0, INTERFACE_INVAL}, {0, INTERFACE_INVAL}, {0, INTERFACE_INVAL} } },   // core_idx = 4 - slice 2 FW
       { { {2, INTERFACE_FWD0}, {2, INTERFACE_FWD1}, {2, INTERFACE_TX0},   {2, INTERFACE_TX1},   {0, INTERFACE_INVAL} } },   // core_idx = 5 - slice 2 FW and TX
       { { {0, INTERFACE_TERM}, {0, INTERFACE_INVAL},{0, INTERFACE_INVAL}, {0, INTERFACE_INVAL}, {0, INTERFACE_INVAL} } },   // core_idx = 6 - slice 0 Term
       { { {1, INTERFACE_TERM}, {2, INTERFACE_TERM}, {0, INTERFACE_INVAL}, {0, INTERFACE_INVAL}, {0, INTERFACE_INVAL} } },   // core_idx = 7 - slice 1,2 Term
}};


// map between slice ifs to result channel
const std::array<std::array<ctm::slice_interface_out_desc,ctm::NUM_INTERFACES_PER_SLICE >, ctm::NUM_SLICES> ctm_config_tcam::s_ctm_slice_ifs_mapping_stand_alone_out = {{
      //  INTERFACE_TERM,    INTERFACE_FWD0,    INTERFACE_FWD1,    INTERFACE_TX0,    INTERFACE_TX1,
        { { {6, 0},            {0, 1},            {0, 2},            {0, 3},           {IDX_INVAL, CHANNEL_INVAL} } },   // slice 0 {ring, result channel}
        { { {6, 1},            {1, 1},            {1, 2},            {1, 3},           {IDX_INVAL, CHANNEL_INVAL} } },   // slice 1 {ring, result channel}
        { { {6, 2},            {2, 1},            {2, 2},            {2, 3},           {IDX_INVAL, CHANNEL_INVAL} } },   // slice 2 {ring, result channel}
        { { {7, 0},            {3, 1},            {3, 2},            {3, 3},           {IDX_INVAL, CHANNEL_INVAL} } },   // slice 3 {ring, result channel}
        { { {7, 1},            {4, 1},            {4, 2},            {4, 3},           {IDX_INVAL, CHANNEL_INVAL} } },   // slice 4 {ring, result channel}
        { { {7, 2},            {5, 1},            {5, 2},            {5, 3},           {IDX_INVAL, CHANNEL_INVAL} } },   // slice 5 {ring, result channel}
}};
const std::array<std::array<ctm::slice_interface_out_desc, ctm::NUM_INTERFACES_PER_SLICE>, ctm::NUM_SLICES> ctm_config_tcam::s_ctm_slice_ifs_mapping_line_card_out = {{
      //   INTERFACE_TERM,             INTERFACE_FWD0,            INTERFACE_FWD1,             INTERFACE_TX0,              INTERFACE_TX1,
        { { {6, 0},                     {0, RES_CHAN_DBM0},         {0, 1},                     {1, 2},                     {IDX_INVAL, CHANNEL_INVAL} } },   // slice 0 {ring, result channel}
        { { {7, 0},                     {2, RES_CHAN_DBM1},         {2, 1},                     {3, 2},                     {IDX_INVAL, CHANNEL_INVAL} } },   // slice 1 {ring, result channel}
        { { {7, 1},                     {4, RES_CHAN_DBM2},         {4, 1},                     {5, 2},                     {IDX_INVAL, CHANNEL_INVAL} } },   // slice 2 {ring, result channel}
        { { {IDX_INVAL, CHANNEL_INVAL}, {IDX_INVAL, CHANNEL_INVAL}, {IDX_INVAL, CHANNEL_INVAL}, {IDX_INVAL, CHANNEL_INVAL}, {IDX_INVAL, CHANNEL_INVAL} } },   // slice 3 NA for line card
        { { {IDX_INVAL, CHANNEL_INVAL}, {IDX_INVAL, CHANNEL_INVAL}, {IDX_INVAL, CHANNEL_INVAL}, {IDX_INVAL, CHANNEL_INVAL}, {IDX_INVAL, CHANNEL_INVAL} } },   // slice 4 NA for line card
        { { {IDX_INVAL, CHANNEL_INVAL}, {IDX_INVAL, CHANNEL_INVAL}, {IDX_INVAL, CHANNEL_INVAL}, {IDX_INVAL, CHANNEL_INVAL}, {IDX_INVAL, CHANNEL_INVAL} } },   // slice 5 NA for line card
}};

// clang-format on

} // namespace silicon_one
