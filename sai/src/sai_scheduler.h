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

#ifndef __SAI_SCHEDULER_H__
#define __SAI_SCHEDULER_H__

#include <jansson.h>
#include <unordered_set>

extern "C" {
#include <sai.h>
}

#include "sai_db.h"
#include "sai_utils.h"
#include "sai_warm_boot.h"

namespace silicon_one
{
namespace sai
{

class lasai_scheduling_params
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    friend class lasai_tm;

public:
    static constexpr float SYSTEM_PORT_SPEEDUP = 1.2; // compensate for NPU header overhead

public:
    lasai_scheduling_params()
    {
    }
    explicit lasai_scheduling_params(sai_scheduling_type_t type,
                                     uint8_t weight = 1,
                                     uint64_t pir = 0,
                                     sai_meter_type_t meter_type = SAI_METER_TYPE_BYTES)
        : m_type(type), m_weight(weight), m_pir(pir), m_meter_type(meter_type)
    {
    }
    sai_scheduling_type_t type() const
    {
        return m_type;
    }
    uint8_t weight() const
    {
        return m_weight;
    }
    uint64_t pir() const
    {
        return m_pir;
    }
    sai_meter_type_t meter_type() const
    {
        return m_meter_type;
    }
    void set_type(sai_scheduling_type_t type)
    {
        m_type = type;
    }
    void set_weight(uint8_t weight)
    {
        m_weight = weight;
    }
    void set_pir(uint64_t pir)
    {
        // Store the pir in bits per second since sdk does not to bytes per second
        m_pir = pir * 8;
    }
    void set_meter_type(sai_meter_type_t meter_type)
    {
        m_meter_type = meter_type;
    }

private:
    sai_scheduling_type_t m_type;
    uint8_t m_weight = 0;
    uint64_t m_pir = 0;
    sai_meter_type_t m_meter_type = SAI_METER_TYPE_BYTES;
    std::unordered_set<sai_object_id_t> m_using_ports; // ports using this scheduler (on at least one of their queue)
};

class lasai_tm
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    friend class lsai_device;

    static const uint32_t MAX_SCHEDULERS = 1000;

public:
    lasai_tm() = default; // for warm boot
    lasai_tm(std::shared_ptr<lsai_device> sai_dev) : m_lsai_device(sai_dev)
    {
    }

    static void scheduler_id_to_str(_In_ sai_object_id_t scheduler_id, _Out_ char* key_str);

    static sai_status_t sai_scheduler_attr_scheduling_type_set(_In_ const sai_object_key_t* key,
                                                               _In_ const sai_attribute_value_t* value,
                                                               void* arg);

    static sai_status_t sai_scheduler_attr_scheduling_type_get(_In_ const sai_object_key_t* key,
                                                               _Inout_ sai_attribute_value_t* attr,
                                                               _In_ uint32_t attr_index,
                                                               _Inout_ vendor_cache_t* cache,
                                                               void* arg);
    static sai_status_t sai_scheduler_attr_meter_type_get(_In_ const sai_object_key_t* key,
                                                          _Inout_ sai_attribute_value_t* attr,
                                                          _In_ uint32_t attr_index,
                                                          _Inout_ vendor_cache_t* cache,
                                                          void* arg);
    static sai_status_t sai_scheduler_attr_scheduling_weight_set(_In_ const sai_object_key_t* key,
                                                                 _In_ const sai_attribute_value_t* value,
                                                                 void* arg);

    static sai_status_t sai_scheduler_attr_scheduling_weight_get(_In_ const sai_object_key_t* key,
                                                                 _Inout_ sai_attribute_value_t* attr,
                                                                 _In_ uint32_t attr_index,
                                                                 _Inout_ vendor_cache_t* cache,
                                                                 void* arg);

    static sai_status_t sai_scheduler_attr_max_bandwidth_rate_set(_In_ const sai_object_key_t* key,
                                                                  _In_ const sai_attribute_value_t* value,
                                                                  void* arg);

    static sai_status_t sai_scheduler_attr_max_bandwidth_rate_get(_In_ const sai_object_key_t* key,
                                                                  _Inout_ sai_attribute_value_t* attr,
                                                                  _In_ uint32_t attr_index,
                                                                  _Inout_ vendor_cache_t* cache,
                                                                  void* arg);

    static sai_status_t sai_scheduler_attr_meter_type_set(_In_ const sai_object_key_t* key,
                                                          _In_ const sai_attribute_value_t* value,
                                                          void* arg);

    static sai_status_t sai_scheduler_attr_min_bandwidth_get(_In_ const sai_object_key_t* key,
                                                             _Inout_ sai_attribute_value_t* attr,
                                                             _In_ uint32_t attr_index,
                                                             _Inout_ vendor_cache_t* cache,
                                                             void* arg);

    sai_status_t get_type(sai_object_id_t oid, sai_scheduling_type_t& type);
    sai_status_t get_weight(sai_object_id_t oid, uint8_t& weigth);
    sai_status_t get_pir(sai_object_id_t oid, uint64_t& pir);
    sai_status_t get_meter_type(sai_object_id_t oid, uint32_t& meter_type);
    void create_default_scheduler();
    sai_object_id_t default_scheduler();
    void update_scheduler_used_ports(sai_object_id_t port_oid, sai_object_id_t new_sched_oid, sai_object_id_t old_sched_oid);
    static sai_status_t get_scheduler_attribute(_In_ sai_object_id_t scheduler_id,
                                                _In_ uint32_t attr_count,
                                                _Inout_ sai_attribute_t* attr_list);
    static sai_status_t set_scheduler_attribute(_In_ sai_object_id_t scheduler_id, _In_ const sai_attribute_t* attr);
    static sai_status_t remove_scheduler(_In_ sai_object_id_t scheduler_id);
    static sai_status_t create_scheduler(_Out_ sai_object_id_t* out_scheduler_id,
                                         _In_ sai_object_id_t switch_id,
                                         _In_ uint32_t attr_count,
                                         _In_ const sai_attribute_t* attr_list);
    void dump_json(json_t* parent_json) const;

private:
    static sai_status_t check_and_get_device_and_scheduler_index(_In_ sai_object_id_t obj_id,
                                                                 _In_ sai_object_type_t type,
                                                                 _Out_ std::shared_ptr<lsai_device>& out_sdev,
                                                                 _Out_ uint32_t& out_id);
    static sai_status_t get_scheduler_and_check_attr(_In_ const sai_object_key_t* key,
                                                     _Inout_ sai_attribute_value_t* attr,
                                                     _Out_ lasai_scheduling_params& scheduler);

private:
    obj_db<lasai_scheduling_params> m_scheduler_db{SAI_OBJECT_TYPE_SCHEDULER, MAX_SCHEDULERS};
    std::shared_ptr<lsai_device> m_lsai_device;
    sai_object_id_t m_default_scheduler = 0;
};
}
}
#endif
