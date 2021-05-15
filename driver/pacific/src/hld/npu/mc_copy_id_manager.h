// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __MC_COPY_ID_MANAGER_H__
#define __MC_COPY_ID_MANAGER_H__

namespace silicon_one
{

class mc_copy_id_manager
{
public:
    // Get the MC-copy-ID from the CUD table entry index
    static uint64_t cud_entry_index_2_mc_copy_id(uint64_t cud_entry_index)
    {
        return (CUD_MAP_PREFIX_PADDED | cud_entry_index);
    }

    // Get CUD table entry index from the the MC-copy-ID
    static uint64_t mc_copy_id_2_cud_entry_index(uint64_t mc_copy_id)
    {
        return (mc_copy_id & (~CUD_MAP_PREFIX_MASK));
    }

private:
    enum {
        CUD_MAP_PREFIX_PADDED = 0b10101 << 13,
        CUD_MAP_PREFIX_MASK = 0b11111 << 13,
    };
};

} // namespace silicon_one

#endif // __MC_COPY_ID_MANAGER_H__
