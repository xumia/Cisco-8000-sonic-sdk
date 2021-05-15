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

#ifndef __SAI_SAMPLEPACKET_H__
#define __SAI_SAMPLEPACKET_H__

extern "C" {
#include <sai.h>
}

#include "api/system/la_device.h"
#include "api/system/la_l2_mirror_command.h"
#include "api/system/la_erspan_mirror_command.h"
#include "common/cereal_utils.h"
#include "common/ranged_index_generator.h"
#include "sai_constants.h"
#include "sai_db.h"
#include "sai_utils.h"
#include "sai_mirror.h"

namespace silicon_one
{
namespace sai
{

struct port_entry;

struct lasai_samplepacket_t {
    // Object id when a new sample packet is created.
    sai_object_id_t samplepacket_oid = SAI_NULL_OBJECT_ID;
    // Type of packet sampling object. When type is slow path
    // sampled packets are directed to cpu. When type is mirror
    // using regular mirror objects, packets are sampled at
    // the rate specified by sample packet object but using
    // mirror encap information, destination etc  from mirror session object.
    sai_samplepacket_type_t type = SAI_SAMPLEPACKET_TYPE_SLOW_PATH;
    // At present only exclusive mode is supported. Shared mode is
    // to be supported in future.
    sai_samplepacket_mode_t mode = SAI_SAMPLEPACKET_MODE_EXCLUSIVE;
    // Rate of sampling to be used in packet sampling for slow-path,
    // sample mirror instances.
    uint32_t sample_rate;
    // Mirror session created when samplepacket type is slow path. Otherwise
    // regular mirror objects have to be provided for sampling. Those mirror
    // objects are not owned by sampling object. Such mirror objects are applied
    // by refering lasai_mirror_session_t db.
    sai_object_id_t slow_path_mirror_session_oid;
    // List of ports on which packet sample is attached for sampling ingress traffic
    std::set<sai_object_id_t> ingress_packet_sampled_port_oids;
    // List of ports on which packet sample is attached for sampling egress traffic
    std::set<sai_object_id_t> egress_packet_sampled_port_oids;
};

class sai_samplepacket
{
public:
    CEREAL_SUPPORT_PRIVATE_MEMBERS

    sai_samplepacket();
    sai_samplepacket(std::shared_ptr<lsai_device> sai_dev);
    ~sai_samplepacket();
    la_status allocate_samplepacket_instance(uint32_t& samplepacket_id);
    void free_samplepacket_instance(uint32_t samplepacket_id);
    static sai_status_t samplepacket_attrib_get(_In_ const sai_object_key_t* key,
                                                _Inout_ sai_attribute_value_t* value,
                                                _In_ uint32_t attr_index,
                                                _Inout_ vendor_cache_t* cache,
                                                void* arg);
    static sai_status_t update_sampling_rate_on_all_gress_sample_mirror_instances(
        uint32_t sample_rate,
        bool is_ingress_stage,
        const std::set<sai_object_id_t>& sampled_port_oids);
    static sai_status_t update_sampling_rate_on_all_sample_mirror_objects(lasai_samplepacket_t* samplepacket);
    static sai_status_t samplepacket_attrib_set(_In_ const sai_object_key_t* key,
                                                _In_ const sai_attribute_value_t* value,
                                                void* arg);
    static sai_status_t create_samplepacket(_Out_ sai_object_id_t* samplepacket_id,
                                            _In_ sai_object_id_t switch_id,
                                            _In_ uint32_t attr_count,
                                            _In_ const sai_attribute_t* attr_list);
    static sai_status_t remove_samplepacket(_In_ sai_object_id_t samplepacket_id);
    static sai_status_t set_samplepacket_attribute(_In_ sai_object_id_t samplepacket_id, _In_ const sai_attribute_t* attr);
    static sai_status_t get_samplepacket_attribute(_In_ sai_object_id_t samplepacket_id,
                                                   _In_ uint32_t attr_count,
                                                   _Inout_ sai_attribute_t* attr_list);
    static std::string samplepacket_attr_to_string(sai_attribute_t& attr);

    sai_status_t port_packet_sampling_set(const sai_object_key_t* key, bool is_ingress_stage, sai_object_id_t packet_sample_oid);
    sai_status_t port_sample_mirror_session_set(const sai_object_key_t* key,
                                                bool is_ingress_stage,
                                                const std::vector<sai_object_id_t>& new_mirror_session_oids_to_sample);

private:
    sai_status_t create_slow_path_samplepacket(transaction& txn,
                                               const lsai_object& la_obj,
                                               lasai_mirror_session_t& mirror_session,
                                               lasai_samplepacket_t& samplepacket);

    sai_status_t create_mirror_type_samplepacket(transaction& txn, lasai_samplepacket_t& samplepacket);
    sai_status_t process_sample_mirror_sessions(std::shared_ptr<lsai_device>& sdev,
                                                port_entry* pentry,
                                                bool is_ingress_stage,
                                                const std::vector<sai_object_id_t>& mirror_session_oids);
    sai_status_t attach_sample_mirror_session(const std::shared_ptr<lsai_device>& sdev,
                                              port_entry* pentry,
                                              bool is_ingress_stage,
                                              sai_object_id_t packet_sample_oid,
                                              lasai_samplepacket_t* packet_sample,
                                              sai_object_id_t mirror_oid);
    sai_status_t attach_sample_mirror_sessions(port_entry* pentry,
                                               bool is_ingress_stage,
                                               sai_object_id_t packet_sample_oid,
                                               const std::vector<sai_object_id_t>& mirror_session_oids);
    sai_status_t detach_and_delete_sample_mirror_sessions(const std::shared_ptr<lsai_device>& sdev,
                                                          port_entry* pentry,
                                                          bool is_ingress_stage);
    sai_status_t detach_sample_mirror_sessions(const std::shared_ptr<lsai_device>& sdev, port_entry* pentry, bool is_ingress_stage);
    sai_status_t attach_packet_sample_instance(port_entry* pentry, bool is_ingress_stage, sai_object_id_t packet_sample_oid);

private:
    std::shared_ptr<lsai_device> m_sdev;

public:
    obj_db<lasai_samplepacket_t> m_samplepacket_db;
};
}
}

#endif //__SAI_SAMPLEPACKET_H__
