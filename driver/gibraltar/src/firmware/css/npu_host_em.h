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

#ifndef __NPU_HOST_EM_H__
#define __NPU_HOST_EM_H__

enum em_command_e {
    EM_COMMAND_LOOKUP = 0,      ///< Lookup key. Return entry and location.
    EM_COMMAND_WRITE = 1,       ///< Writes entry to location. Overrides existing entry if needed.
    EM_COMMAND_FFE = 2,         ///< Find Free Entry for key
    EM_COMMAND_READ = 3,        ///< Reads entry for provided location
    EM_COMMAND_POP = 4,         ///< Obsolete operation
    EM_COMMAND_DELETE = 5,      ///< Delete entry
    EM_COMMAND_QUICK_INSERT = 8 ///< Inserts entry if can find a location
};

#pragma pack(push, 1)

/// @brief EM request
struct em_request_data {
    uint64_t payload : 40;
    uint64_t key : 50;
    uint64_t em_index : 11;
    uint64_t em_bank_bitset : 4;
    uint64_t for_cam : 1;
    uint64_t command : 4;
    uint64_t padding : 18;
} __attribute__((aligned(4)));

/// @brief EM response
struct em_response_data {
    uint64_t valid : 1;
    uint64_t payload : 40;
    uint64_t key : 50;
    uint64_t em_index : 11;
    uint64_t em_bank : 2;
    uint64_t for_cam : 1;
    uint64_t command : 4;
    uint64_t hit : 1; /// < command success
    uint64_t padding : 18;

} __attribute__((aligned(4)));

#pragma pack(pop)

bool npuh_em_add_entry(arc_context_t* ctx, uint64_t key);
bool npuh_em_delete_entry(arc_context_t* ctx, uint64_t key);

#endif //  __NPU_HOST_EM_H__
