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

#ifndef __SAI_MPLS_H__
#define __SAI_MPLS_H__

#include <memory>
#include <unordered_map>

#include "api/npu/la_mpls_vpn_decap.h"
#include "api/npu/la_lsr.h"
#include "common/ranged_index_generator.h"
#include "common/transaction.h"

#include "saimpls.h"
#include "saiobject.h"
#include "saistatus.h"

#include "sai_utils.h"
#include "sai_warm_boot.h"

namespace silicon_one
{
namespace sai
{

class lsai_device;

class inseg_params
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

    friend class mpls_handler;

public:
    inseg_params()
    {
    }
    inseg_params(sai_object_id_t next_hop, uint8_t num_of_pop) : m_next_hop(next_hop), m_num_of_pop(num_of_pop)
    {
    }

private:
    la_obj_wrap<la_mpls_vpn_decap> m_mpls_vpn_decap;
    sai_object_id_t m_next_hop = SAI_NULL_OBJECT_ID;
    uint8_t m_num_of_pop = 0;
};

class mpls_handler
{
    static constexpr uint32_t MAX_PREFIX_OBJECT_GIDS = (1 << 16);

    CEREAL_SUPPORT_PRIVATE_MEMBERS
public:
    mpls_handler() = default; // for warm boot
    mpls_handler(std::shared_ptr<lsai_device> sai_dev) : m_sai_device(sai_dev), m_prefix_object_ids(0, MAX_PREFIX_OBJECT_GIDS){};

    la_status inseg_next_hop_id_set_internal(std::shared_ptr<lsai_device> sdev,
                                             const sai_inseg_entry_t* inseg_entry,
                                             inseg_params& new_inseg);

    la_status initialize(transaction& txn, std::shared_ptr<lsai_device> sdev);
    la_status allocate_gid(uint32_t& gid);
    void release_gid(uint32_t gid);
    void clear_inseg_entry(la_lsr* lsr, const sai_inseg_entry_t* inseg_entry);
    static sai_status_t inseg_entry_attrib_get(_In_ const sai_object_key_t* key,
                                               _Inout_ sai_attribute_value_t* value,
                                               _In_ uint32_t attr_index,
                                               _Inout_ vendor_cache_t* cache,
                                               void* arg);
    static sai_status_t inseg_entry_attrib_set(_In_ const sai_object_key_t* key,
                                               _In_ const sai_attribute_value_t* value,
                                               void* arg);
    static sai_status_t create_inseg_entry(const sai_inseg_entry_t* inseg_entry,
                                           uint32_t attr_count,
                                           const sai_attribute_t* attr_list);
    static sai_status_t remove_inseg_entry(const sai_inseg_entry_t* inseg_entry);
    static sai_status_t set_inseg_entry_attribute(const sai_inseg_entry_t* inseg_entry, const sai_attribute_t* attr);
    static sai_status_t get_inseg_entry_attribute(const sai_inseg_entry_t* inseg_entry,
                                                  uint32_t attr_count,
                                                  sai_attribute_t* attr_list);

private:
    std::shared_ptr<lsai_device> m_sai_device = nullptr;
    std::unordered_map<sai_label_id_t, inseg_params> m_label_map;
    ranged_index_generator m_prefix_object_ids;
};
}
}
#endif
