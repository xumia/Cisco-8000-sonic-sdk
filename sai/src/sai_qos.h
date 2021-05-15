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

#ifndef __SAI_QOS_H__
#define __SAI_QOS_H__

#include <jansson.h>
#include <memory>
#include <unordered_map>

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
struct lasai_qos_map_list_t {
    /** Number of entries in the map */
    uint32_t count;
    sai_qos_map_t* list;

    /** Map list */
    std::shared_ptr<sai_qos_map_t> shared_list;
};

class lasai_to_sdk_qos_base
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    // need virtual destructor for serialization tool
    virtual ~lasai_to_sdk_qos_base() = default;

    void inc_ref_count()
    {
        m_reference_count++;
    }

    void dec_ref_count()
    {
        m_reference_count--;
    }

    uint32_t ref_count() const
    {
        return m_reference_count;
    }

protected:
    uint32_t m_reference_count = 0;
};

class lasai_to_sdk_qos_ingress : public lasai_to_sdk_qos_base
{
public:
    lasai_to_sdk_qos_ingress() = default;
    virtual ~lasai_to_sdk_qos_ingress() = default;

public:
    uint32_t m_dscp_to_color;
    uint32_t m_dscp_to_tc;
    uint32_t m_pcpdei_to_color;
    uint32_t m_pcpdei_to_tc;
    uint32_t m_mpls_to_tc;
    uint32_t m_mpls_to_color;
    la_obj_wrap<la_ingress_qos_profile> m_sdk_profile;
};

class lasai_to_sdk_qos_egress : public lasai_to_sdk_qos_base
{
public:
    lasai_to_sdk_qos_egress() = default;
    virtual ~lasai_to_sdk_qos_egress() = default;

public:
    la_obj_wrap<la_egress_qos_profile> m_sdk_profile;
};

class lasai_to_sdk_tc_profile : public lasai_to_sdk_qos_base
{
public:
    virtual ~lasai_to_sdk_tc_profile() = default;

public:
    uint32_t m_tc_to_queue;
    la_obj_wrap<la_tc_profile> m_sdk_profile;
};

class lasai_qos_map
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    friend class lasai_qos;

public:
    explicit lasai_qos_map(sai_qos_map_type_t type = SAI_QOS_MAP_TYPE_CUSTOM_RANGE_BASE, uint32_t element_count = 0)
        : m_map_type(type)
    {
        m_value_mapping.count = element_count;
        if (element_count != 0) {
            m_value_mapping.shared_list
                = std::shared_ptr<sai_qos_map_t>(new sai_qos_map_t[element_count], std::default_delete<sai_qos_map_t[]>());
            m_value_mapping.list = m_value_mapping.shared_list.get();
        } else {
            m_value_mapping.list = nullptr;
        }
    }

private:
    sai_qos_map_type_t m_map_type;
    lasai_qos_map_list_t m_value_mapping;
    uint32_t m_reference_count = 0;
};

class lasai_qos
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    friend class lsai_device;

    static const uint32_t MAX_QOS_MAPS = 1000;
    static const uint32_t SAI_QOS_NON_VALID_INDEX = 0xFFFF;
    static const uint32_t MAX_QOS_TC_VAL = 7;
    static const uint32_t MAX_QOS_DSCP_VAL = 63;
    static const uint32_t MAX_QOS_DOT1P_VAL = 15;
    static const uint32_t MAX_QOS_PRIO_VAL = 0; // We don't support this
    static const uint32_t MAX_QOS_PG_VAL = 0;   // We don't support this
    static const uint32_t MAX_QOS_QUEUE_INDEX_VAL = 7;
    static const la_qos_color_e MAX_QOS_COLOR_VAL = la_qos_color_e::RED;

public:
    lasai_qos() = default; // for warm boot
    lasai_qos(std::shared_ptr<lsai_device> sai_dev);

    // QOS_MAP static handler functions
    static sai_status_t verify_limits(sai_qos_map_t& qos_entry);
    static sai_status_t create_qos_map(_Out_ sai_object_id_t* qos_map_id,
                                       _In_ sai_object_id_t switch_id,
                                       _In_ uint32_t attr_count,
                                       _In_ const sai_attribute_t* attr_list);
    static sai_status_t remove_qos_map(_In_ sai_object_id_t qos_map_id);
    static sai_status_t set_qos_map_attribute(_In_ sai_object_id_t qos_map_id, _In_ const sai_attribute_t* attr);
    static sai_status_t get_qos_map_attribute(_In_ sai_object_id_t qos_map_id,
                                              _In_ uint32_t attr_count,
                                              _Inout_ sai_attribute_t* attr_list);
    static sai_status_t sai_qos_map_attr_type_get(_In_ const sai_object_key_t* key,
                                                  _Inout_ sai_attribute_value_t* value,
                                                  _In_ uint32_t attr_index,
                                                  _Inout_ vendor_cache_t* cache,
                                                  void* arg);
    static sai_status_t sai_qos_map_attr_list_set(_In_ const sai_object_key_t* key,
                                                  _In_ const sai_attribute_value_t* value,
                                                  void* arg);
    static sai_status_t sai_qos_map_attr_list_get(_In_ const sai_object_key_t* key,
                                                  _Inout_ sai_attribute_value_t* value,
                                                  _In_ uint32_t attr_index,
                                                  _Inout_ vendor_cache_t* cache,
                                                  void* arg);

    // Switch attributes handler functions
    static sai_status_t switch_attr_qos_map_set(_In_ const sai_object_key_t* key,
                                                _In_ const sai_attribute_value_t* value,
                                                void* arg);
    static sai_status_t switch_attr_qos_map_get(_In_ const sai_object_key_t* key,
                                                _Inout_ sai_attribute_value_t* value,
                                                _In_ uint32_t attr_index,
                                                _Inout_ vendor_cache_t* cache,
                                                void* arg);
    static sai_status_t switch_attr_tc_map_set(_In_ const sai_object_key_t* key,
                                               _In_ const sai_attribute_value_t* value,
                                               void* arg);
    static sai_status_t switch_attr_tc_map_get(_In_ const sai_object_key_t* key,
                                               _Inout_ sai_attribute_value_t* value,
                                               _In_ uint32_t attr_index,
                                               _Inout_ vendor_cache_t* cache,
                                               void* arg);
    la_status initialize_default_qos_profiles(transaction& txn, std::shared_ptr<lsai_device> sdev);
    // QOS functions for leaba
    la_status initialize_default_ingress_qos_profile(transaction& txn);
    la_status initialize_default_egress_qos_profile(transaction& txn);

    la_status create_sdk_ingress_qos_profile(transaction& txn, std::unique_ptr<lasai_to_sdk_qos_ingress>& out_prof_info);
    static la_status configure_sdk_ingress_qos_profile(std::shared_ptr<lsai_device> sdev,
                                                       const lasai_to_sdk_qos_ingress& prof_info,
                                                       bool program_defaults);
    la_status create_sdk_egress_qos_profile(transaction& txn, std::unique_ptr<lasai_to_sdk_qos_egress>& out_prof_info);
    static la_status configure_sdk_egress_qos_profile(const lasai_to_sdk_qos_egress& prof_info);
    la_status create_sdk_tc_profile(transaction& txn, std::unique_ptr<lasai_to_sdk_tc_profile>& prof_info);
    static la_status configure_sdk_tc_profile(std::shared_ptr<lsai_device> sdev, const lasai_to_sdk_tc_profile& prof_info);
    la_ingress_qos_profile* get_default_ingress_qos_profile() const;
    la_egress_qos_profile* get_default_egress_qos_profile() const;
    la_tc_profile* get_default_tc_profile() const;
    void dump_json(json_t* parent_json) const;
    void dump();

private:
    static void qos_map_id_to_str(_In_ sai_object_id_t qos_map_id, _Out_ char* key_str);
    static sai_status_t check_and_get_device_and_map_id(const sai_object_id_t& qos_map_id,
                                                        std::shared_ptr<lsai_device>& out_sdev,
                                                        uint32_t& out_map_id,
                                                        lasai_qos_map& out_qos_map);
    static sai_status_t check_switch_params_and_get_device_and_map_index(const sai_object_key_t* key,
                                                                         const sai_attribute_value_t* value,
                                                                         std::shared_ptr<lsai_device>& sdev,
                                                                         uint32_t& map_index,
                                                                         sai_qos_map_type_t map_type);
    static la_qos_color_e sai_color_to_la_color(sai_packet_color_t sai_color);

private:
    // translate map type to the relevant default map
    std::unordered_map<uint32_t, sai_object_id_t> m_default_qos_maps;
    obj_db<lasai_qos_map> m_qos_map_db{SAI_OBJECT_TYPE_QOS_MAP, MAX_QOS_MAPS};
    std::shared_ptr<lsai_device> m_lsai_device;

    std::unique_ptr<lasai_to_sdk_qos_ingress> m_default_ingress_qos_profile = nullptr;
    std::unique_ptr<lasai_to_sdk_qos_egress> m_default_egress_qos_profile = nullptr;
    std::unique_ptr<lasai_to_sdk_tc_profile> m_default_tc_profile = nullptr;
};
}
}

#ifdef ENABLE_SERIALIZATION
#include "common/cereal_utils.h"

namespace cereal
{
template <class Archive>
void save(Archive&, const silicon_one::sai::lasai_qos_map_list_t&);
template <class Archive>
void load(Archive&, silicon_one::sai::lasai_qos_map_list_t&);
}
#endif
#endif //__SAI_QOS_H__
